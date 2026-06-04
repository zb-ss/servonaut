"""Walk an EC2 instance's ALB/WAF ingress path in one call.

Backs the ``describe_ingress_path`` tool. During the incident, ~6 rounds went
to proving "behind ALB, not direct", discovering mod_remoteip, and finding the
WAF wasn't even attached to the right ALB. This service answers all of that at
once:

    instance → target group(s) → load balancer(s) → listeners/rules
             → associated WebACL → IP sets + rate-based rules

Design notes:

- **Partial-failure tolerant.** The incident agent had an incomplete IAM
  scope (wafv2 denied). Every phase is wrapped: an ``AccessDenied`` on the WAF
  walk still returns the target-group + load-balancer topology, with the
  failure recorded in ``errors``. We never raise out of the walk — a partial
  map beats a hard failure.
- **boto3 runs in a thread** (``run_in_executor``) like CloudWatchService, so
  the TUI stays responsive.
- Matches an instance target by BOTH instance-id (instance-type target
  groups) and private IP (ip-type target groups).
- mod_remoteip trust is NOT determined here — that's an on-box fact the tool
  layer adds (memory / SSH). This service is pure AWS topology.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

import boto3

logger = logging.getLogger(__name__)


class IngressPathService:
    """Resolve the ALB/WAF ingress topology fronting an EC2 instance."""

    async def describe(
        self, instance_id: str, private_ip: str = "", region: str = "",
    ) -> Dict[str, Any]:
        """Return the ingress topology for *instance_id* (boto3 in a thread)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._describe_sync, instance_id, private_ip, region,
        )

    # ------------------------------------------------------------------
    # Sync walk
    # ------------------------------------------------------------------

    def _describe_sync(
        self, instance_id: str, private_ip: str, region: str,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "instance_id": instance_id,
            "region": region,
            "target_groups": [],
            "load_balancers": [],
            "errors": [],
        }
        kwargs = {"region_name": region} if region else {}

        try:
            elbv2 = boto3.client("elbv2", **kwargs)
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(f"elbv2 client: {exc}")
            return result

        # --- target groups containing this instance -------------------
        matched_tgs = self._find_target_groups(
            elbv2, instance_id, private_ip, result["errors"],
        )
        result["target_groups"] = [
            {k: tg[k] for k in ("name", "arn", "port", "protocol", "target_state")}
            for tg in matched_tgs
        ]

        # --- load balancers fronting those target groups --------------
        lb_arns: List[str] = []
        for tg in matched_tgs:
            for arn in tg.get("lb_arns", []):
                if arn not in lb_arns:
                    lb_arns.append(arn)
        if not lb_arns:
            return result

        load_balancers = self._describe_load_balancers(
            elbv2, lb_arns, result["errors"],
        )

        # --- listeners + rules per LB ---------------------------------
        our_tg_arns = {tg["arn"] for tg in matched_tgs}
        for lb in load_balancers:
            lb["listeners"] = self._describe_listeners(
                elbv2, lb["arn"], result["errors"], our_tg_arns,
            )

        # --- WebACL per (application) LB ------------------------------
        wafv2 = None
        try:
            wafv2 = boto3.client("wafv2", **kwargs)
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(f"wafv2 client: {exc}")
        if wafv2 is not None:
            for lb in load_balancers:
                if lb.get("type") and lb["type"] != "application":
                    # Only ALBs can carry a WAFv2 WebACL.
                    lb["web_acl"] = None
                    continue
                lb["web_acl"] = self._describe_web_acl(
                    wafv2, lb["arn"], region, result["errors"],
                )

        result["load_balancers"] = load_balancers
        return result

    def _find_target_groups(
        self, elbv2, instance_id: str, private_ip: str, errors: List[str],
    ) -> List[Dict[str, Any]]:
        matched: List[Dict[str, Any]] = []
        targets = {t for t in (instance_id, private_ip) if t}
        try:
            paginator = elbv2.get_paginator("describe_target_groups")
            tgs = []
            for page in paginator.paginate():
                tgs.extend(page.get("TargetGroups", []))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"describe_target_groups: {exc}")
            return matched

        for tg in tgs:
            arn = tg.get("TargetGroupArn", "")
            try:
                health = elbv2.describe_target_health(TargetGroupArn=arn)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"describe_target_health({tg.get('TargetGroupName')}): {exc}")
                continue
            state = None
            for desc in health.get("TargetHealthDescriptions", []):
                tid = desc.get("Target", {}).get("Id", "")
                if tid in targets:
                    state = desc.get("TargetHealth", {}).get("State")
                    break
            if state is None:
                continue
            matched.append({
                "name": tg.get("TargetGroupName", ""),
                "arn": arn,
                "port": tg.get("Port"),
                "protocol": tg.get("Protocol", ""),
                "target_state": state,
                "lb_arns": tg.get("LoadBalancerArns", []),
            })
        return matched

    def _describe_load_balancers(
        self, elbv2, lb_arns: List[str], errors: List[str],
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            resp = elbv2.describe_load_balancers(LoadBalancerArns=lb_arns)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"describe_load_balancers: {exc}")
            # Still return ARNs we know about so the agent sees the linkage.
            return [{"arn": a, "dns_name": "", "type": "", "scheme": "",
                     "listeners": [], "web_acl": None} for a in lb_arns]
        for lb in resp.get("LoadBalancers", []):
            out.append({
                "arn": lb.get("LoadBalancerArn", ""),
                "dns_name": lb.get("DNSName", ""),
                "type": lb.get("Type", ""),
                "scheme": lb.get("Scheme", ""),
                "listeners": [],
                "web_acl": None,
            })
        return out

    def _describe_listeners(
        self, elbv2, lb_arn: str, errors: List[str], our_tg_arns=None,
    ) -> List[Dict[str, Any]]:
        our_tg_arns = our_tg_arns or set()
        listeners: List[Dict[str, Any]] = []
        try:
            resp = elbv2.describe_listeners(LoadBalancerArn=lb_arn)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"describe_listeners: {exc}")
            return listeners
        for li in resp.get("Listeners", []):
            li_arn = li.get("ListenerArn", "")
            entry = {
                "port": li.get("Port"),
                "protocol": li.get("Protocol", ""),
                "rules": [],
            }
            try:
                rules_resp = elbv2.describe_rules(ListenerArn=li_arn)
                entry["rules"] = [
                    self._summarize_rule(r, our_tg_arns)
                    for r in rules_resp.get("Rules", [])
                ]
            except Exception as exc:  # noqa: BLE001
                errors.append(f"describe_rules: {exc}")
            listeners.append(entry)
        return listeners

    @staticmethod
    def _rule_target_arns(rule: Dict[str, Any]) -> List[str]:
        """All target-group ARNs a rule forwards to (direct + ForwardConfig)."""
        arns: List[str] = []
        for a in rule.get("Actions", []):
            if a.get("TargetGroupArn"):
                arns.append(a["TargetGroupArn"])
            for tg in a.get("ForwardConfig", {}).get("TargetGroups", []):
                if tg.get("TargetGroupArn"):
                    arns.append(tg["TargetGroupArn"])
        return arns

    @staticmethod
    def _summarize_rule(rule: Dict[str, Any], our_tg_arns=None) -> Dict[str, Any]:
        our_tg_arns = our_tg_arns or set()
        conditions: List[str] = []
        for cond in rule.get("Conditions", []):
            field = cond.get("Field", "")
            values = cond.get("Values", []) or [
                v for vk in ("HostHeaderConfig", "PathPatternConfig")
                if (vk in cond) for v in cond[vk].get("Values", [])
            ]
            conditions.append(f"{field}={','.join(values)}" if values else field)
        actions = [a.get("Type", "") for a in rule.get("Actions", [])]
        targets = IngressPathService._rule_target_arns(rule)
        return {
            "priority": rule.get("Priority", ""),
            "conditions": conditions,
            "actions": actions,
            # True when this rule routes to the target group holding our instance
            # — the rule(s) that actually matter for this box.
            "targets_our_tg": any(a in our_tg_arns for a in targets),
        }

    def _describe_web_acl(
        self, wafv2, lb_arn: str, region: str, errors: List[str],
    ) -> Optional[Dict[str, Any]]:
        # ALB → REGIONAL scope. (CLOUDFRONT scope is global/us-east-1 and only
        # applies to CloudFront distributions, not ALBs.)
        try:
            resp = wafv2.get_web_acl_for_resource(ResourceArn=lb_arn)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"get_web_acl_for_resource: {exc}")
            return None
        summary = resp.get("WebACL")
        if not summary:
            return None  # No WebACL attached — a key incident finding.
        acl = {
            "arn": summary.get("ARN", ""),
            "name": summary.get("Name", ""),
            "ip_sets": [],
            "rate_rules": [],
        }
        # get_web_acl needs Name + Id + Scope to read the rule set.
        try:
            full = wafv2.get_web_acl(
                Name=summary.get("Name", ""),
                Scope="REGIONAL",
                Id=summary.get("Id", ""),
            )
            web_acl = full.get("WebACL", {})
            acl["default_action"] = (
                "allow" if "Allow" in web_acl.get("DefaultAction", {}) else "block"
            )
            for r in web_acl.get("Rules", []):
                self._collect_rule_refs(r, acl)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"get_web_acl({summary.get('Name')}): {exc}")
        return acl

    def _collect_rule_refs(self, rule: Dict[str, Any], acl: Dict[str, Any]) -> None:
        """Pull IP-set references and rate-based rules out of one WebACL rule."""
        stmt = rule.get("Statement", {})
        name = rule.get("Name", "")
        # IP set reference (possibly nested under And/Or/Not — scan recursively).
        for ip_arn in self._scan_ipset_arns(stmt):
            acl["ip_sets"].append({"rule": name, "arn": ip_arn})
        # Rate-based rule (top level or as a scope-down container).
        rate = self._find_rate_statement(stmt)
        if rate is not None:
            acl["rate_rules"].append({
                "rule": name,
                "limit_per_5min": rate.get("Limit"),
                "aggregate_key": rate.get("AggregateKeyType", "IP"),
            })

    def _scan_ipset_arns(self, stmt: Dict[str, Any]) -> List[str]:
        found: List[str] = []
        if not isinstance(stmt, dict):
            return found
        if "IPSetReferenceStatement" in stmt:
            arn = stmt["IPSetReferenceStatement"].get("ARN", "")
            if arn:
                found.append(arn)
        for key in ("AndStatement", "OrStatement"):
            for sub in stmt.get(key, {}).get("Statements", []):
                found.extend(self._scan_ipset_arns(sub))
        if "NotStatement" in stmt:
            found.extend(self._scan_ipset_arns(stmt["NotStatement"].get("Statement", {})))
        return found

    def _find_rate_statement(self, stmt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(stmt, dict):
            return None
        if "RateBasedStatement" in stmt:
            return stmt["RateBasedStatement"]
        for key in ("AndStatement", "OrStatement"):
            for sub in stmt.get(key, {}).get("Statements", []):
                found = self._find_rate_statement(sub)
                if found is not None:
                    return found
        return None


def _format_web_acl(acl: Optional[Dict[str, Any]], lb: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    if acl is None:
        lines.append(
            f"  WebACL fronting {lb.get('dns_name', lb.get('arn', '?'))}: "
            "NONE attached"
            + (" ⚠ (ALB has no WAF in front of it — a flood hits the app "
               "directly)" if lb.get("type") == "application" else ""))
        return lines
    lines.append(f"  WebACL: {acl.get('name', '')} "
                 f"(default={acl.get('default_action', '?')})  on "
                 f"{lb.get('dns_name', '')}")
    for ips in acl.get("ip_sets", []):
        lines.append(f"    IP set (rule {ips.get('rule', '')}): {ips.get('arn', '')}")
    for rr in acl.get("rate_rules", []):
        lines.append(f"    rate rule '{rr.get('rule', '')}': "
                     f"{rr.get('limit_per_5min', '?')}/5min by "
                     f"{rr.get('aggregate_key', 'IP')}")
    if not acl.get("ip_sets") and not acl.get("rate_rules"):
        lines.append("    (no IP-set or rate-based rules)")
    return lines


def format_ingress_path(
    topo: Dict[str, Any], mod_remoteip_trusted: Optional[bool],
    verbose: bool = False,
) -> str:
    """Render the topology as a skimmable report (WebACL first; verbatim-relayed).

    Listener rules are collapsed to the one(s) routing to THIS instance's target
    group plus a count of the rest (an ALB can carry 100+ host-header rules);
    pass ``verbose=True`` to show every rule.
    """
    out: List[str] = []
    out.append(f"Ingress path for {topo.get('instance_id', '?')} "
               f"(region {topo.get('region') or 'default'}):")

    trust = (
        "yes" if mod_remoteip_trusted is True
        else "no" if mod_remoteip_trusted is False
        else "unknown"
    )
    out.append(f"  mod_remoteip / real-IP trust on box: {trust}")
    if mod_remoteip_trusted is False:
        out.append("    ⚠ %h in access logs is the ALB hop, not the client — "
                   "iptables/host bans by %h will NOT match real clients; "
                   "block at the WebACL.")

    lbs = topo.get("load_balancers", [])

    # WebACL FIRST — it's the gold (which WAF fronts the box, its IP sets +
    # rate rules; or the critical "no WAF attached" finding).
    if lbs:
        out.append("\n  == WAF / WebACL ==")
        for lb in lbs:
            out.extend(_format_web_acl(lb.get("web_acl"), lb))

    tgs = topo.get("target_groups", [])
    if not tgs:
        out.append("\n  No target groups contain this instance — it is NOT "
                   "behind an ALB/NLB (or you lack elbv2:Describe*). Traffic "
                   "may be hitting it directly.")
    else:
        out.append(f"\n  Target groups ({len(tgs)}):")
        for tg in tgs:
            out.append(f"    {tg.get('name','')}  "
                       f"{tg.get('protocol','')}:{tg.get('port','')}  "
                       f"target={tg.get('target_state','?')}")

    if lbs:
        out.append(f"\n  Load balancers ({len(lbs)}):")
        for lb in lbs:
            out.append(f"    {lb.get('type','?')} {lb.get('dns_name','')} "
                       f"({lb.get('scheme','')})")
            for li in lb.get("listeners", []):
                rules = li.get("rules", [])
                matching = [r for r in rules if r.get("targets_our_tg")]
                shown = rules if verbose else (matching or rules[:1])
                out.append(f"      listener {li.get('protocol','')}:"
                           f"{li.get('port','')} ({len(rules)} rule(s))")
                for rule in shown:
                    conds = "; ".join(rule.get("conditions", [])) or "default"
                    acts = ",".join(rule.get("actions", []))
                    mark = " ←this instance" if rule.get("targets_our_tg") else ""
                    out.append(f"        rule[{rule.get('priority','')}] "
                               f"{conds} → {acts}{mark}")
                hidden = len(rules) - len(shown)
                if hidden > 0:
                    out.append(f"        +{hidden} other rule(s) "
                               "(other vhosts/targets — pass verbose=true to see)")

    errors = topo.get("errors", [])
    if errors:
        out.append("\n  Partial result — some calls failed "
                   "(likely missing IAM scope):")
        for e in errors[:10]:
            out.append(f"    - {e}")

    return "\n".join(out)
