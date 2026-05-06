"""Single source of truth for Servonaut's MCP + chat tool metadata.

Both the MCP server (stdio JSON-RPC) and the built-in TUI chat (LLM
function-calling) derive their tool lists from this dict. When adding a new
tool, put the schema here; both surfaces pick it up automatically.

Per-tool shape::

    {
        "description": "One-line summary the LLM / agent sees.",
        "schema":      {"type": "object", "properties": {...}, "required": [...]},
        "chat_exposed": True | False,   # whether the built-in chat's LLM
                                        # should see this tool
        "required_service": "ovh" | None,  # skip registration if service
                                           # is unavailable at runtime
    }

The implementation for each tool lives on :class:`servonaut.mcp.tools.ServonautTools`;
method name == tool name. Dispatchers look up ``getattr(tools, name)``.
"""
from __future__ import annotations

from typing import Any, Dict


TOOL_SCHEMAS: Dict[str, Dict[str, Any]] = {
    # --- Instance inventory + ops ---------------------------------------
    "list_instances": {
        "description": (
            "List all managed server instances (AWS EC2, OVH, custom servers). "
            "Optionally filter by region or state."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "region": {
                    "type": "string",
                    "description": "Filter by region or provider "
                                   "(e.g. 'us-east-1', 'custom', 'OVH').",
                },
                "state": {
                    "type": "string",
                    "description": "Instance state filter (running, stopped, ...).",
                },
            },
        },
        "chat_exposed": True,
    },
    "check_status": {
        "description": "Check status of any managed instance (state, IPs, region, type).",
        "schema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID, name, or custom-server name.",
                },
            },
            "required": ["instance_id"],
        },
        "chat_exposed": True,
    },
    "get_server_info": {
        "description": "Get detailed server info from any managed instance "
                       "(hostname, uptime, disk, memory).",
        "schema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID, name, or custom-server name.",
                },
            },
            "required": ["instance_id"],
        },
        "chat_exposed": True,
    },
    "run_command": {
        "description": "Run a command on any managed instance via SSH.",
        "schema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID, name, or custom-server name.",
                },
                "command": {"type": "string", "description": "Command to execute."},
            },
            "required": ["instance_id", "command"],
        },
        "chat_exposed": True,
    },
    "get_logs": {
        "description": "Get log file content from any managed instance.",
        "schema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID, name, or custom-server name.",
                },
                "log_path": {
                    "type": "string",
                    "description": "Log file path.",
                    "default": "/var/log/syslog",
                },
                "lines": {
                    "type": "integer",
                    "description": "Number of lines to retrieve.",
                    "default": 100,
                },
            },
            "required": ["instance_id"],
        },
        "chat_exposed": True,
    },
    "transfer_file": {
        "description": "Transfer a file via SCP to or from any managed instance.",
        "schema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID, name, or custom-server name.",
                },
                "local_path": {"type": "string"},
                "remote_path": {"type": "string"},
                "direction": {"type": "string", "enum": ["upload", "download"]},
            },
            "required": ["instance_id", "local_path", "remote_path", "direction"],
        },
        "chat_exposed": False,  # guard treats this as dangerous; not for LLM freehand
    },

    # --- OVH -------------------------------------------------------------
    "ovh_monitoring": {
        "description": "Get CPU/RAM/network monitoring data for an OVH instance.",
        "schema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "OVH instance ID or name.",
                },
                "period": {
                    "type": "string",
                    "enum": ["lastday", "lastweek", "lastmonth", "lastyear"],
                    "description": "Monitoring period (default: lastday).",
                },
            },
            "required": ["instance_id"],
        },
        "chat_exposed": False,
        "required_service": "ovh",
    },
    "ovh_list_ips": {
        "description": "List all IPs on the OVH account with type and routing info.",
        "schema": {"type": "object", "properties": {}},
        "chat_exposed": False,
        "required_service": "ovh",
    },
    "ovh_firewall_rules": {
        "description": "List firewall rules for an OVH IP address.",
        "schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address (e.g. '1.2.3.4')."},
            },
            "required": ["ip"],
        },
        "chat_exposed": False,
        "required_service": "ovh",
    },
    "ovh_ssh_keys": {
        "description": "List SSH keys registered on the OVH account.",
        "schema": {"type": "object", "properties": {}},
        "chat_exposed": False,
        "required_service": "ovh",
    },
    "ovh_snapshots": {
        "description": "List snapshots for an OVH VPS or Public Cloud instance.",
        "schema": {
            "type": "object",
            "properties": {
                "instance_id": {"type": "string", "description": "OVH instance ID or name."},
            },
            "required": ["instance_id"],
        },
        "chat_exposed": False,
        "required_service": "ovh",
    },
    "ovh_dns_records": {
        "description": "List DNS records for an OVH zone.",
        "schema": {
            "type": "object",
            "properties": {
                "zone": {"type": "string", "description": "DNS zone name."},
                "record_type": {
                    "type": "string",
                    "description": "Optional record type filter (A, MX, CNAME, ...).",
                },
            },
            "required": ["zone"],
        },
        "chat_exposed": False,
        "required_service": "ovh",
    },
    "ovh_billing": {
        "description": "Get current OVH billing summary including spend and forecast.",
        "schema": {"type": "object", "properties": {}},
        "chat_exposed": False,
        "required_service": "ovh",
    },
    "ovh_invoices": {
        "description": "List recent OVH invoices.",
        "schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of invoices to return (default: 5).",
                },
            },
        },
        "chat_exposed": False,
        "required_service": "ovh",
    },

    # --- Session + backend -----------------------------------------------
    "whoami": {
        "description": (
            "Describe the currently logged-in servonaut.dev session (email, "
            "plan, API base URL, token expiry). The OAuth bearer itself is "
            "never returned."
        ),
        "schema": {"type": "object", "properties": {}},
        "chat_exposed": True,
    },
    "api_request": {
        "description": (
            "Make an authenticated request against the servonaut.dev REST API "
            "using the CLI's OAuth bearer. The bearer never leaves the CLI. "
            "Returns {status, headers, body} or a structured {error} envelope."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                    "description": "HTTP method.",
                },
                "path": {
                    "type": "string",
                    "description": "Relative path starting with '/' (e.g. '/api/cli/status').",
                },
                "query": {
                    "type": ["object", "null"],
                    "description": "Optional querystring parameters as a flat object.",
                },
                "body": {"description": "Optional JSON-serialisable request body."},
                "headers": {
                    "type": ["object", "null"],
                    "description": (
                        "Optional extra headers. Only Accept, Content-Type, "
                        "Accept-Language, and If-None-Match are honoured; "
                        "everything else (including Authorization) is dropped."
                    ),
                },
            },
            "required": ["method", "path"],
        },
        # Intentionally not chat-exposed: the LLM doesn't need to call the REST
        # API directly — run_command, check_status, etc. cover its use cases,
        # and api_request is powerful enough that an agent could paint itself
        # into a corner hitting arbitrary endpoints. Kept visible over MCP so
        # external agents can use it under their own guard policy.
        "chat_exposed": False,
    },
    "relay_status": {
        "description": (
            "Report what servonaut.dev knows about the local CLI's relay "
            "connection (connected flag, last heartbeat, client_ids)."
        ),
        "schema": {"type": "object", "properties": {}},
        "chat_exposed": False,  # operational, not agentic
    },
    "relay_reconnect": {
        "description": (
            "Heal a stale Mercure relay connection. Consults the backend's "
            "/api/cli/status first and no-ops if the listener is healthy; "
            "otherwise SIGTERMs the recorded PID and launches a fresh "
            "background listener. Pass force=true to skip the health-check."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "force": {
                    "type": "boolean",
                    "description": "Restart even if the backend reports the "
                                   "listener as connected (default: false).",
                },
            },
        },
        "chat_exposed": False,
    },
    "mcp_tool_call": {
        "description": (
            "Invoke a tool on the hosted MCP server at mcp.servonaut.dev. "
            "Wraps (name, arguments) into a JSON-RPC 2.0 tools/call envelope "
            "and returns the raw JSON-RPC response."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Hosted MCP tool name."},
                "arguments": {
                    "type": ["object", "null"],
                    "description": "Arguments object passed through.",
                },
            },
            "required": ["name"],
        },
        "chat_exposed": False,
    },

    # --- Server memory -------------------------------------------------------
    "get_server_memory": {
        "description": (
            "Return cached memory (OS, runtimes, services, web stack, logs) for "
            "a managed instance. Call FIRST before issuing SSH commands — the "
            "cached summary frequently answers OS/runtime/service/web-stack "
            "questions without an SSH round-trip. "
            "If this returns an error with code='missing', the server has no "
            "memory yet — call build_server_memory(instance_id) to probe and "
            "populate it, then retry this tool. "
            "format='summary' (default) gives a token-efficient Markdown digest; "
            "format='markdown' gives the full untruncated version; "
            "format='full' returns the raw JSON for all modules; "
            "format='context_block' returns a <CONTEXT name=\"server_memory:...\" "
            "snapshot_at=\"...\"> envelope identical to what the first-party "
            "Servonaut chat client injects — use this when you want a single "
            "drop-in block to prepend to your own model context. "
            "Note: format='full' returns structured per-module data (observed, "
            "declared, probed_at, ttl_seconds, sudo_used, truncated, partial, "
            "raw_output). raw_output is scrubbed of secrets by the redaction "
            "library when config.memory.redaction_enabled is true (default)."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID, name, or custom-server name.",
                },
                "format": {
                    "type": "string",
                    "enum": ["summary", "full", "markdown", "context_block"],
                    "description": "Output format (default: summary).",
                    "default": "summary",
                },
            },
            "required": ["instance_id"],
        },
        "chat_exposed": True,
    },
    "build_server_memory": {
        "description": (
            "Build memory from scratch for a managed instance — probes all "
            "enabled modules (OS, runtimes, services, web stack, logs, etc.) "
            "over SSH and writes the results to the local cache. "
            "Call this when get_server_memory returns code='missing', or when "
            "you want a fresh full scan. "
            "Returns JSON with: instance_id, count (successful modules), "
            "successes (list of module names), failures (list of "
            "{module, reason, message}), and — when count=0 — an overall "
            "'reason' code (opt_out | disabled | no_modules_matched | "
            "all_probers_failed). If reason='all_probers_failed' the failures "
            "list explains per-module (usually an SSH reachability / auth "
            "problem — fix that before retrying)."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID, name, or custom-server name.",
                },
                "modules": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Module names to probe (e.g. ['os', 'runtimes']). "
                        "Omit to probe all enabled modules."
                    ),
                },
            },
            "required": ["instance_id"],
        },
        "chat_exposed": True,
    },
    "refresh_server_memory": {
        "description": (
            "Re-probe memory modules for a managed instance and overwrite the "
            "cache. Functionally equivalent to build_server_memory (probes run "
            "the same way); use this name when updating existing memory after "
            "a deploy/upgrade, and build_server_memory when no memory exists "
            "yet. Returns the same structured JSON with per-module "
            "successes/failures."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID, name, or custom-server name.",
                },
                "modules": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Module names to refresh (e.g. ['os', 'runtimes']). "
                        "Omit to refresh all modules."
                    ),
                },
            },
            "required": ["instance_id"],
        },
        "chat_exposed": True,
    },
    "list_server_memories": {
        "description": (
            "List all instances that have cached server memory. "
            "Set stale_only=true to show only instances with at least one "
            "module whose data has exceeded its TTL."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "stale_only": {
                    "type": "boolean",
                    "description": "When true, return only entries with stale modules.",
                },
            },
        },
        "chat_exposed": True,
    },
}


def mcp_tool_list(have_ovh: bool = True) -> list:
    """Build the list of ``mcp.types.Tool`` objects for the MCP server.

    OVH-gated tools are dropped when the OVH service isn't wired up — agents
    querying ``tools/list`` get a clean view of what's actually callable.
    """
    from mcp.types import Tool
    out = []
    for name, spec in TOOL_SCHEMAS.items():
        if spec.get("required_service") == "ovh" and not have_ovh:
            continue
        out.append(Tool(
            name=name,
            description=spec["description"],
            inputSchema=spec["schema"],
        ))
    return out


def chat_tool_list() -> list:
    """Build the list of tool definitions in the LLM function-calling shape.

    Filters to tools with ``chat_exposed=True``; returns the schema under
    ``parameters`` rather than ``inputSchema`` to match what the chat
    service currently consumes (see ``chat_tool_converters.py``).
    """
    out = []
    for name, spec in TOOL_SCHEMAS.items():
        if not spec.get("chat_exposed"):
            continue
        out.append({
            "name": name,
            "description": spec["description"],
            "parameters": spec["schema"],
        })
    return out


def chat_tool_names() -> set:
    """Set of tool names the chat adapter is allowed to dispatch."""
    return {name for name, spec in TOOL_SCHEMAS.items() if spec.get("chat_exposed")}
