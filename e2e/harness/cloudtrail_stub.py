"""A local CloudTrail ``LookupEvents`` endpoint.

moto does not implement ``LookupEvents``, so this small HTTP server answers
it instead. boto3 reaches it through ``AWS_ENDPOINT_URL_CLOUDTRAIL``, the
service-specific form of the endpoint variable the moto fixture sets, so the
product code is unchanged.

It follows the real API where Servonaut depends on it:

- the JSON 1.1 protocol, dispatched on ``X-Amz-Target``;
- events per region (the region comes from the request's signing scope),
  newest first, inside ``StartTime``..``EndTime``;
- at most 50 events per call, continued with an opaque ``NextToken``;
- only the FIRST lookup attribute is applied, as the real API does.

Seeded events use the shape boto3 returns (``EventTime`` a datetime,
``CloudTrailEvent`` a JSON string). :func:`cloudtrail_event` builds one.
"""

from __future__ import annotations

import base64
import json
import re
import threading
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterable, Optional

API_PAGE_SIZE = 50
_TARGET_PREFIX = "CloudTrail_20131101."
_SCOPE_REGION = re.compile(r"Credential=[^/]+/\d{8}/([a-z0-9-]+)/cloudtrail/")
_ATTRIBUTE_FIELDS = {
    "EventName": lambda event: [event.get("EventName")],
    "Username": lambda event: [event.get("Username")],
    "ResourceType": lambda event: [r.get("ResourceType") for r in event.get("Resources", [])],
    "ResourceName": lambda event: [r.get("ResourceName") for r in event.get("Resources", [])],
    "EventSource": lambda event: [event.get("EventSource")],
    "EventId": lambda event: [event.get("EventId")],
}


def cloudtrail_event(
    name: str,
    when: datetime,
    *,
    username: str,
    region: str = "us-east-1",
    source_ip: str = "10.0.1.21",
    resources: Iterable[dict] = (),
    error_code: str = "",
    identity_type: str = "IAMUser",
) -> dict:
    """One management event, as ``lookup_events`` returns it."""
    detail: dict[str, Any] = {
        "eventVersion": "1.08",
        "userIdentity": {"type": identity_type},
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": "ec2.amazonaws.com",
        "eventName": name,
        "awsRegion": region,
        "sourceIPAddress": source_ip,
        "userAgent": "e2e-agent",
    }
    if error_code:
        detail["errorCode"] = error_code
    return {
        "EventId": str(uuid.uuid4()),
        "EventName": name,
        "ReadOnly": "true" if name.startswith("Describe") else "false",
        "EventTime": when,
        "EventSource": "ec2.amazonaws.com",
        "Username": username,
        "Resources": list(resources),
        "CloudTrailEvent": json.dumps(detail),
    }


def _epoch(value: Any) -> Optional[float]:
    return float(value) if isinstance(value, (int, float)) else None


def _wire(event: dict) -> dict:
    """An event as it travels in a JSON 1.1 response."""
    wire = dict(event)
    wire["EventTime"] = event["EventTime"].timestamp()
    return wire


class CloudTrailStub:
    """The endpoint plus a log of the lookups it answered."""

    def __init__(self) -> None:
        self._events: dict[str, list[dict]] = {}
        self._lookups: list[dict] = []
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler_class())
        self._server.daemon_threads = True
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "CloudTrailStub":
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="cloudtrail-stub", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=10)

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
            self._lookups.clear()

    def seed(self, events: Iterable[dict], *, region: str = "us-east-1") -> None:
        with self._lock:
            stored = self._events.setdefault(region, [])
            stored.extend(events)
            stored.sort(key=lambda event: event["EventTime"], reverse=True)

    def lookups(self) -> list[dict]:
        """Every ``LookupEvents`` request received: region and parameters."""
        with self._lock:
            return [dict(entry) for entry in self._lookups]

    # ------------------------------------------------------------------
    # The API
    # ------------------------------------------------------------------

    def _lookup(self, region: str, params: dict) -> dict:
        with self._lock:
            self._lookups.append({"region": region, **params})
            events = list(self._events.get(region, []))
        start, end = _epoch(params.get("StartTime")), _epoch(params.get("EndTime"))
        attributes = params.get("LookupAttributes") or []
        attribute = attributes[0] if attributes else None
        selected = []
        for event in events:
            stamp = event["EventTime"].timestamp()
            if (start is not None and stamp < start) or (end is not None and stamp > end):
                continue
            if attribute is not None:
                values = _ATTRIBUTE_FIELDS[attribute["AttributeKey"]](event)
                if attribute["AttributeValue"] not in values:
                    continue
            selected.append(event)
        offset = 0
        if params.get("NextToken"):
            offset = int(base64.urlsafe_b64decode(params["NextToken"]).decode())
        size = min(int(params.get("MaxResults") or API_PAGE_SIZE), API_PAGE_SIZE)
        page = selected[offset : offset + size]
        body: dict[str, Any] = {"Events": [_wire(event) for event in page]}
        if offset + size < len(selected):
            body["NextToken"] = base64.urlsafe_b64encode(str(offset + size).encode()).decode()
        return body

    def _handler_class(self) -> type:
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server API
                length = int(self.headers.get("Content-Length") or 0)
                params = json.loads(self.rfile.read(length) or b"{}")
                target = self.headers.get("X-Amz-Target", "")
                operation = target.rsplit(".", 1)[-1] if _TARGET_PREFIX in target else ""
                scope = _SCOPE_REGION.search(self.headers.get("Authorization", ""))
                if operation != "LookupEvents" or scope is None:
                    self._reply(400, {"__type": "UnknownOperationException", "message": target})
                    return
                self._reply(200, stub._lookup(scope.group(1), params))

            def _reply(self, status: int, body: dict) -> None:
                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/x-amz-json-1.1")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return  # keep the journey output clean

        return Handler

