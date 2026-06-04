"""Enrich IP addresses with rDNS, ASN/org, geolocation and abuse score.

Backs the ``enrich_ips`` MCP/chat tool. During an incident the agent has a
list of offender IPs and needs to decide *how* to block them — a single /32
through rotation is whack-a-mole, but an ASN/org (e.g. a bulletproof host)
can be blocked wholesale. This service answers "who owns these IPs and how
bad are they" in one call.

Data sources (both free):

- **ip-api.com** ``/batch`` — geolocation + ASN + org + reverse DNS for up
  to 100 IPs per request. No key. Rate-limited (~15 req/min) so we batch.
- **AbuseIPDB** ``/check`` — abuse confidence score, only when the operator
  has configured ``config.abuseipdb_api_key`` (``$ENV_VAR`` syntax honoured,
  matching the CloudWatch Top-IPs feature).

Transport: prefers ``httpx`` (the optional ``[ai]`` extra) but falls back to
the stdlib ``urllib`` so the headless ``--mcp`` build works without it. All
blocking IO is pushed to a thread via ``run_in_executor`` to stay async.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_IP_API_BATCH_URL = "http://ip-api.com/batch"
# query is appended as a query-string field list; ``reverse`` triggers rDNS.
_IP_API_FIELDS = "status,message,query,country,countryCode,isp,org,as,reverse,proxy,hosting"
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Defensive caps so a runaway agent can't issue thousands of lookups.
_MAX_IPS = 100
_HTTP_TIMEOUT = 10


def _resolve_key(raw: str) -> str:
    """Resolve a config value that may use ``$ENV_VAR`` indirection."""
    raw = (raw or "").strip()
    if raw.startswith("$"):
        return os.environ.get(raw[1:], "")
    return raw


class IPEnrichmentService:
    """Look up ownership + abuse metadata for a batch of IPs."""

    def __init__(self, config_manager=None) -> None:
        self._config_manager = config_manager

    @property
    def max_ips(self) -> int:
        return _MAX_IPS

    def _abuseipdb_key(self) -> str:
        if self._config_manager is None:
            return ""
        config = self._config_manager.get()
        return _resolve_key(getattr(config, "abuseipdb_api_key", "") or "")

    async def enrich(self, ips: List[str]) -> List[Dict[str, Any]]:
        """Return one enrichment dict per input IP (order preserved).

        Each row: ``ip``, ``rdns``, ``asn``, ``org``, ``country``,
        ``hosting`` (bool), ``proxy`` (bool), ``abuse_score`` (int|None),
        ``total_reports`` (int|None), ``error`` (str, when a lookup failed).
        """
        unique = list(dict.fromkeys(i.strip() for i in ips if i and i.strip()))
        if not unique:
            return []
        if len(unique) > _MAX_IPS:
            unique = unique[:_MAX_IPS]

        geo_by_ip = await self._fetch_geo_batch(unique)

        key = self._abuseipdb_key()
        abuse_by_ip: Dict[str, Dict[str, Any]] = {}
        if key:
            # AbuseIPDB free tier has no batch endpoint; check each IP.
            results = await asyncio.gather(
                *(self._fetch_abuse(ip, key) for ip in unique),
                return_exceptions=True,
            )
            for ip, res in zip(unique, results):
                if isinstance(res, dict):
                    abuse_by_ip[ip] = res

        rows: List[Dict[str, Any]] = []
        for ip in unique:
            geo = geo_by_ip.get(ip, {})
            abuse = abuse_by_ip.get(ip, {})
            rows.append({
                "ip": ip,
                "rdns": geo.get("reverse") or "",
                "asn": geo.get("as") or "",
                "org": geo.get("org") or geo.get("isp") or "",
                "country": geo.get("countryCode") or geo.get("country") or "",
                "hosting": bool(geo.get("hosting")),
                "proxy": bool(geo.get("proxy")),
                "abuse_score": abuse.get("abuseConfidenceScore") if abuse else None,
                "total_reports": abuse.get("totalReports") if abuse else None,
                "error": geo.get("_error", ""),
            })
        return rows

    # ------------------------------------------------------------------
    # ip-api.com batch
    # ------------------------------------------------------------------

    async def _fetch_geo_batch(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        payload = [{"query": ip, "fields": _IP_API_FIELDS} for ip in ips]
        try:
            data = await self._post_json(_IP_API_BATCH_URL, payload)
        except Exception as exc:  # noqa: BLE001 — network best-effort
            logger.warning("ip-api batch lookup failed: %s", exc)
            return {ip: {"_error": f"geo lookup failed: {exc}"} for ip in ips}
        out: Dict[str, Dict[str, Any]] = {}
        if isinstance(data, list):
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                q = entry.get("query")
                if not q:
                    continue
                if entry.get("status") != "success":
                    entry = {"_error": entry.get("message", "lookup failed")}
                out[q] = entry
        return out

    async def _fetch_abuse(self, ip: str, key: str) -> Optional[Dict[str, Any]]:
        try:
            data = await self._get_json(
                _ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Key": key, "Accept": "application/json"},
            )
        except Exception as exc:  # noqa: BLE001 — network best-effort
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return None
        if isinstance(data, dict):
            return data.get("data")
        return None

    # ------------------------------------------------------------------
    # Transport (httpx preferred, urllib fallback)
    # ------------------------------------------------------------------

    async def _post_json(self, url: str, body: Any) -> Any:
        try:
            import httpx
        except ImportError:
            return await self._urllib_request(
                url, method="POST", json_body=body,
                headers={"Content-Type": "application/json"},
            )
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.post(url, json=body)
            return resp.json()

    async def _get_json(
        self, url: str, params: Dict[str, str], headers: Dict[str, str],
    ) -> Any:
        try:
            import httpx
        except ImportError:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            return await self._urllib_request(
                f"{url}?{query}", method="GET", headers=headers,
            )
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(url, params=params, headers=headers)
            return resp.json()

    async def _urllib_request(
        self, url: str, method: str,
        json_body: Any = None, headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Blocking urllib request executed in a thread pool."""
        def _do() -> Any:
            data = None
            if json_body is not None:
                data = json.dumps(json_body).encode("utf-8")
            req = urllib.request.Request(
                url, data=data, method=method, headers=headers or {},
            )
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _do)


def format_enrichment(rows: List[Dict[str, Any]]) -> str:
    """Render enrichment rows as a readable table."""
    if not rows:
        return "No valid IP addresses to enrich."
    out: List[str] = [
        f"{'IP':<40} {'Abuse':<7} {'ASN / Org':<32} {'Country':<8} Flags / rDNS",
        "-" * 110,
    ]
    for r in rows:
        score = r.get("abuse_score")
        score_str = f"{score}%" if score is not None else "-"
        asn = r.get("asn") or ""
        org = r.get("org") or ""
        asn_org = (f"{asn} {org}".strip())[:32]
        flags = []
        if r.get("hosting"):
            flags.append("hosting")
        if r.get("proxy"):
            flags.append("proxy")
        if r.get("total_reports"):
            flags.append(f"{r['total_reports']} reports")
        tail = ", ".join(flags)
        if r.get("rdns"):
            tail = f"{tail}  {r['rdns']}" if tail else r["rdns"]
        if r.get("error"):
            tail = r["error"]
        out.append(
            f"{str(r.get('ip', ''))[:40]:<40} "
            f"{score_str:<7} "
            f"{asn_org:<32} "
            f"{str(r.get('country', '') or '-'):<8} "
            f"{tail}"
        )
    return "\n".join(out)
