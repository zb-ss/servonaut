"""Mutating WAFv2 operations for the Group C incident-mitigation tools.

Backs ``waf_rate_rule_set`` and the WebACL paths of ``ip_ban_set`` / ``block_ip``.
The incident lesson was "apply the fix reversibly, at the layer that actually
sees the client IP" — for an ALB-fronted app that layer is the WebACL, not the
host firewall (which only sees the ALB hop) and not a SG/NACL that isn't even
attached to the right ALB.

Everything here MUTATES live traffic handling, so:
- boto3 runs in a thread (``run_in_executor``);
- every method returns a structured dict with ``applied`` + a ``reverse_hint``
  describing exactly how to undo the change (the whole point of the tool);
- methods never raise — failures come back as ``{applied: False, error: ...}``.

A WebACL is identified by (Name, Id, Scope, region). Callers usually have only
an ARN (from ``get_web_acl_for_resource`` or ``describe_ingress_path``);
:func:`parse_wafv2_arn` derives the rest.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional

import boto3

logger = logging.getLogger(__name__)

# arn:aws:wafv2:<region>:<acct>:<regional|global>/<webacl|ipset>/<name>/<id>
_WAF_ARN_RE = re.compile(
    r"^arn:aws:wafv2:(?P<region>[^:]*):[^:]+:"
    r"(?P<scope>regional|global)/(?P<kind>webacl|ipset)/"
    r"(?P<name>[^/]+)/(?P<id>[^/]+)$"
)

# Metric names must be [A-Za-z0-9_]{1,128}.
_METRIC_SAFE_RE = re.compile(r"[^A-Za-z0-9_]")


def parse_wafv2_arn(arn: str) -> Optional[Dict[str, str]]:
    """Parse a WAFv2 ARN into {region, scope, kind, name, id}.

    ``scope`` is normalized to the API form (REGIONAL / CLOUDFRONT).
    """
    m = _WAF_ARN_RE.match(arn or "")
    if not m:
        return None
    d = m.groupdict()
    d["scope"] = "REGIONAL" if d["scope"] == "regional" else "CLOUDFRONT"
    return d


async def resolve_webacl(
    target: str, region: str = "", *, find_instance=None,
) -> Dict[str, Any]:
    """Resolve a WebACL from a WebACL ARN, an ALB ARN, or an instance.

    Returns ``{name, id, scope, region, arn}`` or ``{error}``. For an instance
    it walks the ingress path to find the WebACL fronting its ALB, which needs
    an async ``find_instance(identifier) -> instance dict | None`` callable
    (the MCP tools and the relay executors each supply their own).

    Shared by ``waf_rate_rule_set`` (MCP) and the ``rate_limit`` remediation
    executor so the instance→ALB→WebACL walk has a single implementation. AWS
    resolution runs with the CALLER's credentials, in the caller's context —
    the SaaS server never resolves WebACLs (it holds no AWS creds).
    """
    target = (target or "").strip()
    if not target:
        return {"error": "no target (need a WebACL/ALB ARN or instance)."}

    if target.startswith("arn:aws:wafv2:"):
        parsed = parse_wafv2_arn(target)
        if not parsed or parsed["kind"] != "webacl":
            return {"error": f"not a WebACL ARN: {target}"}
        return {"name": parsed["name"], "id": parsed["id"],
                "scope": parsed["scope"], "region": parsed["region"] or region,
                "arn": target}

    if target.startswith("arn:aws:elasticloadbalancing:"):
        alb_region = (target.split(":")[3] if ":" in target else "") or region
        summ = await WAFManagementService().get_web_acl_for_resource(
            target, alb_region,
        )
        if not summ:
            return {"error": f"no WebACL attached to {target}"}
        parsed = parse_wafv2_arn(summ["arn"])
        return {"name": summ["name"], "id": summ["id"],
                "scope": parsed["scope"] if parsed else "REGIONAL",
                "region": (parsed["region"] if parsed else alb_region) or region,
                "arn": summ["arn"]}

    # Otherwise treat target as an instance id/name → walk its ingress path.
    if find_instance is None:
        return {"error": "no instance resolver available for target"}
    instance = await find_instance(target)
    if not instance:
        return {"error": f"instance not found: {target}"}
    if (instance.get("is_custom") or instance.get("is_ovh")
            or instance.get("is_hetzner")):
        return {"error": f"{target} is not an AWS instance"}
    from servonaut.services.ingress_path_service import IngressPathService
    eff_region = region or instance.get("region") or ""
    topo = await IngressPathService().describe(
        instance.get("id", ""), instance.get("private_ip") or "", eff_region,
    )
    for lb in topo.get("load_balancers", []):
        acl = lb.get("web_acl")
        if acl and acl.get("arn"):
            parsed = parse_wafv2_arn(acl["arn"])
            if parsed:
                return {"name": parsed["name"], "id": parsed["id"],
                        "scope": parsed["scope"],
                        "region": parsed["region"] or eff_region,
                        "arn": acl["arn"]}
    return {"error": f"no WebACL found fronting {target}"}


class WAFManagementService:
    """Add IPs to a WebACL's block IP set, and add/remove rate-based rules."""

    async def get_web_acl_for_resource(
        self, resource_arn: str, region: str = "",
    ) -> Optional[Dict[str, str]]:
        """Return {arn, name, id} of the WebACL fronting an ALB, or None."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._get_web_acl_for_resource_sync, resource_arn, region,
        )

    def _get_web_acl_for_resource_sync(
        self, resource_arn: str, region: str,
    ) -> Optional[Dict[str, str]]:
        kwargs = {"region_name": region} if region else {}
        try:
            client = boto3.client("wafv2", **kwargs)
            resp = client.get_web_acl_for_resource(ResourceArn=resource_arn)
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_web_acl_for_resource(%s): %s", resource_arn, exc)
            return None
        acl = resp.get("WebACL")
        if not acl:
            return None
        return {"arn": acl.get("ARN", ""), "name": acl.get("Name", ""),
                "id": acl.get("Id", "")}

    # ------------------------------------------------------------------
    # Add an IP/CIDR to the IP set referenced by a WebACL's block rule
    # ------------------------------------------------------------------

    async def add_ip_to_block_ipset(
        self, web_acl_name: str, web_acl_id: str, scope: str, region: str,
        cidrs: List[str], remove: bool = False,
    ) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._add_ip_to_block_ipset_sync,
            web_acl_name, web_acl_id, scope, region, cidrs, remove,
        )

    def _add_ip_to_block_ipset_sync(
        self, web_acl_name: str, web_acl_id: str, scope: str, region: str,
        cidrs: List[str], remove: bool,
    ) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "applied": [], "failed": [], "ip_set": "", "error": "",
        }
        kwargs = {"region_name": region} if region else {}
        try:
            client = boto3.client("wafv2", **kwargs)
            acl = client.get_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id)
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"get_web_acl: {exc}"
            return out

        ip_set_arn = self._first_block_ipset_arn(acl.get("WebACL", {}))
        if not ip_set_arn:
            out["error"] = (
                "WebACL has no block rule referencing an IP set. Create an IP "
                "set + block rule first (or use a named ip_ban config / "
                "waf_rate_rule_set)."
            )
            return out
        parsed = parse_wafv2_arn(ip_set_arn)
        if not parsed:
            out["error"] = f"unparseable IP set ARN: {ip_set_arn}"
            return out
        out["ip_set"] = parsed["name"]

        try:
            ipset = client.get_ip_set(
                Name=parsed["name"], Scope=scope, Id=parsed["id"],
            )
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"get_ip_set: {exc}"
            return out
        addresses = list(ipset["IPSet"]["Addresses"])
        lock = ipset["LockToken"]

        changed = False
        for cidr in cidrs:
            norm = cidr if "/" in cidr else f"{cidr}/32"
            if remove:
                if norm in addresses:
                    addresses.remove(norm)
                    out["applied"].append(cidr)
                    changed = True
                else:
                    out["failed"].append({"ip": cidr, "reason": "not present"})
            else:
                if norm in addresses:
                    out["failed"].append({"ip": cidr, "reason": "already present"})
                else:
                    addresses.append(norm)
                    out["applied"].append(cidr)
                    changed = True

        if changed:
            try:
                client.update_ip_set(
                    Name=parsed["name"], Scope=scope, Id=parsed["id"],
                    Addresses=addresses, LockToken=lock,
                )
            except Exception as exc:  # noqa: BLE001
                out["error"] = f"update_ip_set: {exc}"
                # The applied list is now untrustworthy — surface the failure.
                out["failed"].extend({"ip": c, "reason": f"update failed: {exc}"}
                                     for c in out["applied"])
                out["applied"] = []
        return out

    def _first_block_ipset_arn(self, web_acl: Dict[str, Any]) -> Optional[str]:
        """Return the IP set ARN used by the WebACL's first Block rule."""
        for rule in web_acl.get("Rules", []):
            if "Block" not in rule.get("Action", {}):
                continue
            for arn in self._scan_ipset_arns(rule.get("Statement", {})):
                return arn
        # Fall back: any IP-set reference at all (some setups block via default).
        for rule in web_acl.get("Rules", []):
            for arn in self._scan_ipset_arns(rule.get("Statement", {})):
                return arn
        return None

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

    # ------------------------------------------------------------------
    # Add / remove a rate-based rule on a WebACL
    # ------------------------------------------------------------------

    async def set_rate_rule(
        self, web_acl_name: str, web_acl_id: str, scope: str, region: str,
        rule_name: str, limit: int = 2000, uri_scope: str = "",
        action: str = "block", remove: bool = False, ip_scope: str = "",
    ) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._set_rate_rule_sync,
            web_acl_name, web_acl_id, scope, region,
            rule_name, limit, uri_scope, action, remove, ip_scope,
        )

    def _ensure_scope_ipset_sync(
        self, client, scope: str, ip_set_name: str, ip: str,
    ) -> Dict[str, Any]:
        """Find-or-create a dedicated IPSet holding exactly ``ip`` and return
        ``{arn, id, name}`` (or ``{error}``). Used to scope a rate rule to a
        single client IP via an IPSetReferenceStatement — a rate rule with no
        scope-down throttles EVERY ip, so the ip-scoped ``rate_limit`` needs
        its own IPSet, distinct from the shared block IPSet.

        Idempotent: reusing the same ``ip_set_name`` updates its address to the
        current ip rather than creating a duplicate."""
        version = "IPV6" if ipaddress.ip_address(ip).version == 6 else "IPV4"
        addr = f"{ip}/128" if version == "IPV6" else f"{ip}/32"
        try:
            existing = next(
                (s for s in client.list_ip_sets(Scope=scope).get("IPSets", [])
                 if s.get("Name") == ip_set_name),
                None,
            )
        except Exception as exc:  # noqa: BLE001
            return {"error": f"list_ip_sets: {exc}"}
        if existing:
            try:
                got = client.get_ip_set(
                    Name=ip_set_name, Scope=scope, Id=existing["Id"],
                )
                if list(got["IPSet"]["Addresses"]) != [addr]:
                    client.update_ip_set(
                        Name=ip_set_name, Scope=scope, Id=existing["Id"],
                        Addresses=[addr], LockToken=got["LockToken"],
                    )
            except Exception as exc:  # noqa: BLE001
                return {"error": f"update_ip_set: {exc}"}
            return {"arn": existing["ARN"], "id": existing["Id"],
                    "name": ip_set_name}
        try:
            created = client.create_ip_set(
                Name=ip_set_name, Scope=scope, IPAddressVersion=version,
                Addresses=[addr],
                Description="servonaut rate_limit scope (auto-managed)",
            )
        except Exception as exc:  # noqa: BLE001
            return {"error": f"create_ip_set: {exc}"}
        summary = created["Summary"]
        return {"arn": summary["ARN"], "id": summary["Id"], "name": ip_set_name}

    def _rate_rule_state(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Snapshot an existing rate rule's reversible state."""
        rb = rule.get("Statement", {}).get("RateBasedStatement", {})
        return {
            "limit": rb.get("Limit"),
            "uri_scoped": bool(rb.get("ScopeDownStatement")),
            "action": "count" if "Count" in rule.get("Action", {}) else "block",
        }

    def _set_rate_rule_sync(
        self, web_acl_name: str, web_acl_id: str, scope: str, region: str,
        rule_name: str, limit: int, uri_scope: str, action: str, remove: bool,
        ip_scope: str = "",
    ) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "applied": False, "error": "", "rule_name": rule_name,
            "created_or_updated": "", "previous": None,
            "ip_set_arn": "", "ip_set_name": "",
        }
        kwargs = {"region_name": region} if region else {}
        try:
            client = boto3.client("wafv2", **kwargs)
            resp = client.get_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id)
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"get_web_acl: {exc}"
            return out

        web_acl = resp["WebACL"]
        lock = resp["LockToken"]
        rules = list(web_acl.get("Rules", []))
        existing = next((r for r in rules if r.get("Name") == rule_name), None)

        if remove:
            new_rules = [r for r in rules if r.get("Name") != rule_name]
            if len(new_rules) == len(rules):
                out["error"] = f"rule {rule_name!r} not found on WebACL"
                return out
            # Capture what we removed so the caller can re-create it exactly.
            if existing is not None:
                out["previous"] = self._rate_rule_state(existing)
            rules = new_rules
        else:
            # Reversibility: record the prior state when UPDATING an existing
            # rule, so the operator can restore the old limit/action (not just
            # delete the rule). null when newly created.
            if existing is not None:
                out["previous"] = self._rate_rule_state(existing)
            out["created_or_updated"] = "updated" if existing is not None else "created"
            # Build the rate-based rule (replace if a rule of the same name exists
            # so the call is idempotent / used to bump the limit).
            existing_prios = {r.get("Priority", 0) for r in rules
                              if r.get("Name") != rule_name}
            priority = (max(existing_prios) + 1) if existing_prios else 0
            rules = [r for r in rules if r.get("Name") != rule_name]
            rate_stmt: Dict[str, Any] = {
                "Limit": int(limit), "AggregateKeyType": "IP",
            }
            # Scope-down: an ip (rate_limit → throttle only that client, via a
            # dedicated IPSet) OR a uri path (rate_limit_path → throttle each
            # ip's rate on that path). Mutually exclusive per verb.
            if ip_scope:
                ipset = self._ensure_scope_ipset_sync(
                    client, scope, f"{rule_name}-scope", ip_scope,
                )
                if ipset.get("error"):
                    out["error"] = ipset["error"]
                    return out
                out["ip_set_arn"] = ipset["arn"]
                out["ip_set_name"] = ipset["name"]
                rate_stmt["ScopeDownStatement"] = {
                    "IPSetReferenceStatement": {"ARN": ipset["arn"]},
                }
            elif uri_scope:
                rate_stmt["ScopeDownStatement"] = {
                    "ByteMatchStatement": {
                        "SearchString": uri_scope.encode("utf-8"),
                        "FieldToMatch": {"UriPath": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "STARTS_WITH",
                    }
                }
            metric = _METRIC_SAFE_RE.sub("_", rule_name)[:128] or "servonautRate"
            rules.append({
                "Name": rule_name,
                "Priority": priority,
                "Statement": {"RateBasedStatement": rate_stmt},
                "Action": {"Count": {}} if action == "count" else {"Block": {}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": metric,
                },
            })

        update_kwargs = {
            "Name": web_acl_name, "Scope": scope, "Id": web_acl_id,
            "DefaultAction": web_acl["DefaultAction"],
            "Rules": rules,
            "VisibilityConfig": web_acl["VisibilityConfig"],
            "LockToken": lock,
        }
        if web_acl.get("Description"):
            update_kwargs["Description"] = web_acl["Description"]
        if web_acl.get("CustomResponseBodies"):
            update_kwargs["CustomResponseBodies"] = web_acl["CustomResponseBodies"]
        try:
            client.update_web_acl(**update_kwargs)
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"update_web_acl: {exc}"
            return out
        out["applied"] = True
        return out
