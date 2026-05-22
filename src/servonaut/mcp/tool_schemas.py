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

    # --- Hetzner Cloud --------------------------------------------------
    "hetzner_list_servers": {
        "description": (
            "List all Hetzner Cloud servers in the user's project. "
            "Returns name, ID, type, status, public IPv4, and location."
        ),
        "schema": {"type": "object", "properties": {}},
        "chat_exposed": True,
        "required_service": "hetzner",
    },
    "hetzner_list_server_types": {
        "description": (
            "List available Hetzner Cloud server types (cx23, cpx22, "
            "ccx13, ...) with their hourly + monthly EUR prices."
        ),
        "schema": {"type": "object", "properties": {}},
        "chat_exposed": True,
        "required_service": "hetzner",
    },
    "hetzner_list_ssh_keys": {
        "description": (
            "List SSH keys registered with Hetzner Cloud. Use the names "
            "returned here as the ssh_keys argument to hetzner_create_server."
        ),
        "schema": {"type": "object", "properties": {}},
        "chat_exposed": True,
        "required_service": "hetzner",
    },
    "hetzner_delete_ssh_key": {
        "description": (
            "Delete an SSH key from the Hetzner Cloud project's registry "
            "by name or numeric ID. Servers that already had the key "
            "injected at create time are unaffected — the key remains in "
            "their authorized_keys. New servers can no longer reference "
            "it by name. "
            "ALWAYS confirm with the user (state the key name) before "
            "calling."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "identifier": {
                    "type": "string",
                    "description": (
                        "Numeric SSH key ID (as a string) or key name."
                    ),
                },
            },
            "required": ["identifier"],
        },
        "chat_exposed": False,
        "required_service": "hetzner",
    },
    "hetzner_create_ssh_key": {
        "description": (
            "Register a new SSH public key with Hetzner Cloud so it can be "
            "injected into newly-created servers. "
            "Confirm with the user (key name + fingerprint) before calling."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Display name for the key (max 253 chars).",
                },
                "public_key": {
                    "type": "string",
                    "description": (
                        "Full public-key text starting with the algorithm "
                        "prefix (e.g. 'ssh-ed25519 AAA...')."
                    ),
                },
            },
            "required": ["name", "public_key"],
        },
        # State-changing on a remote service; fits standard mode (cost is
        # near-zero, so the dangerous gate is overkill).
        "chat_exposed": False,
        "required_service": "hetzner",
    },
    "hetzner_create_server": {
        "description": (
            "Create a new Hetzner Cloud server and (by default) wait until "
            "it reports 'running'. Returns the new server's instance dict "
            "(id, name, public_ip, ...). The server is automatically "
            "discoverable by other tools (run_command, check_status) on "
            "the next listing cycle. Costs money — only enabled in "
            "dangerous guard mode. "
            "Summarise type/image/location and confirm with the user "
            "before calling."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": (
                        "Server name. Allowed: ASCII alphanumerics, dot, "
                        "dash, underscore (1-253 chars)."
                    ),
                },
                "server_type": {
                    "type": "string",
                    "description": (
                        "Hetzner server-type name (e.g. 'cx23'). Defaults "
                        "to config.hetzner.default_server_type."
                    ),
                },
                "image": {
                    "type": "string",
                    "description": (
                        "Image name (e.g. 'ubuntu-22.04'). Defaults to "
                        "config.hetzner.default_image."
                    ),
                },
                "location": {
                    "type": "string",
                    "description": (
                        "Datacentre location (fsn1/nbg1/hel1/ash/hil). "
                        "Defaults to config.hetzner.default_location."
                    ),
                },
                "ssh_keys": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Names or numeric IDs (as strings) of SSH keys to "
                        "inject. Falls back to "
                        "config.hetzner.default_hetzner_ssh_key when empty."
                    ),
                },
                "wait_until_running": {
                    "type": "boolean",
                    "description": (
                        "Poll until the server reaches 'running' before "
                        "returning (default true)."
                    ),
                },
            },
            "required": ["name"],
        },
        "chat_exposed": False,
        "required_service": "hetzner",
    },
    "hetzner_delete_server": {
        "description": (
            "Delete a Hetzner Cloud server by ID or name. Irreversible "
            "data loss. Only enabled in dangerous guard mode. "
            "ALWAYS confirm with the user (state the exact server name "
            "and any data-loss implications) before calling."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "identifier": {
                    "type": "string",
                    "description": (
                        "Numeric server ID (as a string) or server name."
                    ),
                },
            },
            "required": ["identifier"],
        },
        "chat_exposed": False,
        "required_service": "hetzner",
    },
    "hetzner_power_on": {
        "description": (
            "Boot a stopped Hetzner Cloud server. No-op when already "
            "running. Resumes billing for any usage-priced add-ons. "
            "Confirm the target server with the user before calling."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "identifier": {
                    "type": "string",
                    "description": "Numeric server ID or server name.",
                },
            },
            "required": ["identifier"],
        },
        "chat_exposed": True,
        "required_service": "hetzner",
    },
    "hetzner_power_off": {
        "description": (
            "Hard power off a Hetzner Cloud server (equivalent to pulling the "
            "plug). Use hetzner_shutdown for a graceful ACPI halt unless the "
            "server is unresponsive. Disk state is preserved; billing continues. "
            "Confirm with the user before calling — risks in-flight write loss."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "identifier": {
                    "type": "string",
                    "description": "Numeric server ID or server name.",
                },
            },
            "required": ["identifier"],
        },
        "chat_exposed": True,
        "required_service": "hetzner",
    },
    "hetzner_shutdown": {
        "description": (
            "Send an ACPI shutdown signal to a Hetzner Cloud server (graceful "
            "OS-level halt). Returns once the signal is accepted; the server "
            "may take 10-60 s to fully stop. "
            "Confirm the target server with the user before calling — "
            "outage until the server is started again."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "identifier": {
                    "type": "string",
                    "description": "Numeric server ID or server name.",
                },
            },
            "required": ["identifier"],
        },
        "chat_exposed": True,
        "required_service": "hetzner",
    },
    "hetzner_reboot": {
        "description": (
            "Send a graceful reboot signal (ACPI) to a Hetzner Cloud server. "
            "Server stays billed; data is preserved across the restart. "
            "Confirm with the user before calling — brief service "
            "interruption while the OS restarts."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "identifier": {
                    "type": "string",
                    "description": "Numeric server ID or server name.",
                },
            },
            "required": ["identifier"],
        },
        "chat_exposed": True,
        "required_service": "hetzner",
    },

    # --- OVH instance lifecycle ----------------------------------------
    "ovh_create_instance": {
        "description": (
            "Create an OVH Public Cloud instance. Costs money — billing "
            "starts immediately. Reserved for dangerous guard mode. "
            "Summarise project / flavor / image / region and confirm with "
            "the user before calling."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "project_id": {
                    "type": "string",
                    "description": "OVH Public Cloud project ID.",
                },
                "name": {
                    "type": "string",
                    "description": "Display name for the new instance.",
                },
                "flavor_id": {
                    "type": "string",
                    "description": (
                        "Flavor identifier from list_flavors. Drives the "
                        "instance's vCPU / RAM / disk and price."
                    ),
                },
                "image_id": {
                    "type": "string",
                    "description": "OS image identifier from list_images.",
                },
                "region": {
                    "type": "string",
                    "description": (
                        "OVH datacenter code (e.g. GRA11, SBG5, BHS5)."
                    ),
                },
                "ssh_key_id": {
                    "type": ["string", "null"],
                    "description": (
                        "Optional SSH key identifier from list_ssh_keys to "
                        "inject. Null/empty creates without an injected key "
                        "(rare — only useful for snapshot-based images)."
                    ),
                },
            },
            "required": ["project_id", "name", "flavor_id", "image_id", "region"],
        },
        "chat_exposed": False,
        "required_service": "ovh",
    },
    "ovh_delete_instance": {
        "description": (
            "Delete an OVH Public Cloud instance. Irreversible data "
            "loss; stops billing immediately. Reserved for dangerous "
            "guard mode. ALWAYS confirm with the user (state the exact "
            "project_id / instance_id and any data-loss implications) "
            "before calling."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "project_id": {
                    "type": "string",
                    "description": "OVH Public Cloud project ID.",
                },
                "instance_id": {
                    "type": "string",
                    "description": "Instance identifier (the bare id, "
                                   "not the composite project/id form).",
                },
            },
            "required": ["project_id", "instance_id"],
        },
        "chat_exposed": False,
        "required_service": "ovh",
    },
    "ovh_start_instance": {
        "description": (
            "Start a stopped OVH instance. Supported for VPS and Public "
            "Cloud — dedicated bare-metal does not have a power-on API. "
            "Confirm the target instance with the user before calling — "
            "resumes Cloud billing while the instance is running."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": (
                        "OVH instance identifier. For Cloud instances, "
                        "use the composite '<project_id>/<id>' form so the "
                        "service can route to the right project."
                    ),
                },
                "provider_type": {
                    "type": "string",
                    "enum": ["vps", "cloud"],
                    "description": "OVH resource type.",
                },
            },
            "required": ["instance_id", "provider_type"],
        },
        "chat_exposed": True,
        "required_service": "ovh",
    },
    "ovh_stop_instance": {
        "description": (
            "Stop a running OVH instance (graceful where supported). "
            "Supported for VPS and Public Cloud only. Disk state preserved; "
            "VPS billing continues, Cloud billing pauses while stopped. "
            "Confirm the target instance with the user before calling — "
            "outage until the instance is started again."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": (
                        "OVH instance identifier. For Cloud, use the "
                        "composite '<project_id>/<id>' form."
                    ),
                },
                "provider_type": {
                    "type": "string",
                    "enum": ["vps", "cloud"],
                    "description": "OVH resource type.",
                },
            },
            "required": ["instance_id", "provider_type"],
        },
        "chat_exposed": True,
        "required_service": "ovh",
    },
    "ovh_reboot_instance": {
        "description": (
            "Reboot an OVH instance. Soft reboot for Cloud / VPS, hardware "
            "reboot for dedicated bare-metal. "
            "Confirm the target instance with the user before calling — "
            "brief service interruption while the OS restarts."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": (
                        "OVH instance identifier. For Cloud, use the "
                        "composite '<project_id>/<id>' form."
                    ),
                },
                "provider_type": {
                    "type": "string",
                    "enum": ["dedicated", "vps", "cloud"],
                    "description": "OVH resource type.",
                },
            },
            "required": ["instance_id", "provider_type"],
        },
        "chat_exposed": True,
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
        "required_service": "memory",
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
        "required_service": "memory",
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
        "required_service": "memory",
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
        "required_service": "memory",
    },

    # --- AWS CloudWatch Logs (read-only) --------------------------------
    "cloudwatch_list_log_groups": {
        "description": (
            "List AWS CloudWatch log groups, optionally filtered by name "
            "prefix. Shows stored bytes and retention per group."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "prefix": {
                    "type": "string",
                    "description": "Filter to log groups whose name starts "
                                   "with this prefix.",
                },
                "region": {
                    "type": "string",
                    "description": "AWS region (defaults to the boto3 "
                                   "default region when empty).",
                },
            },
        },
        "chat_exposed": True,
    },
    "cloudwatch_get_log_events": {
        "description": (
            "Fetch recent events from a CloudWatch log group within the "
            "last N hours, with an optional CloudWatch filter pattern."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "log_group": {
                    "type": "string",
                    "description": "CloudWatch log group name.",
                },
                "hours_back": {
                    "type": "integer",
                    "description": "How many hours back to search.",
                    "default": 1,
                },
                "filter_pattern": {
                    "type": "string",
                    "description": "CloudWatch Logs filter pattern (optional).",
                },
                "region": {
                    "type": "string",
                    "description": "AWS region (optional).",
                },
                "max_events": {
                    "type": "integer",
                    "description": "Maximum events to return (0 = unlimited, "
                                   "capped at 50000).",
                    "default": 100,
                },
            },
            "required": ["log_group"],
        },
        "chat_exposed": True,
    },
    "cloudwatch_top_ips": {
        "description": (
            "Rank the top client IPs in a CloudWatch log group. Parses "
            "WAF/ALB structured logs to report per-IP total, allowed, and "
            "blocked counts — use it to find abusive IPs before banning."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "log_group": {
                    "type": "string",
                    "description": "CloudWatch log group name (e.g. a WAF "
                                   "or ALB access-log group).",
                },
                "hours_back": {
                    "type": "integer",
                    "description": "How many hours back to scan.",
                    "default": 24,
                },
                "action_filter": {
                    "type": "string",
                    "description": "Count only events with this WAF action: "
                                   "'ALLOW', 'BLOCK', or empty for all.",
                },
                "region": {
                    "type": "string",
                    "description": "AWS region (optional).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum IPs to return.",
                    "default": 20,
                },
                "max_events": {
                    "type": "integer",
                    "description": "Maximum events to scan (0 = unlimited, "
                                   "capped at 50000).",
                    "default": 0,
                },
            },
            "required": ["log_group"],
        },
        "chat_exposed": True,
    },

    # --- AWS CloudTrail (read-only) -------------------------------------
    "cloudtrail_lookup_events": {
        "description": (
            "Look up AWS CloudTrail management events with optional filters "
            "(event name, username, resource type). Useful for auditing who "
            "changed what, and from which source IP."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "region": {
                    "type": "string",
                    "description": "AWS region. Empty queries the configured "
                                   "default region (or all regions if unset).",
                },
                "hours_back": {
                    "type": "integer",
                    "description": "How many hours back to search. 0 uses the "
                                   "configured default lookback.",
                    "default": 0,
                },
                "event_name": {
                    "type": "string",
                    "description": "Filter by CloudTrail event name "
                                   "(e.g. 'RunInstances').",
                },
                "username": {
                    "type": "string",
                    "description": "Filter by the IAM username.",
                },
                "resource_type": {
                    "type": "string",
                    "description": "Filter by resource type "
                                   "(e.g. 'AWS::EC2::Instance').",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum events to return (0 = unlimited, "
                                   "capped at 10000).",
                    "default": 50,
                },
            },
        },
        "chat_exposed": True,
    },

    # --- IP ban (WAF / Security Group / NACL) --------------------------
    "ip_ban_list_configs": {
        "description": (
            "List the configured IP-ban targets (WAF IP sets, security "
            "groups, or network ACLs) available for ip_ban_set."
        ),
        "schema": {"type": "object", "properties": {}},
        "chat_exposed": True,
        "required_service": "ip_ban",
    },
    "ip_ban_list_banned": {
        "description": (
            "List the IP addresses currently banned under a named IP-ban "
            "configuration."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "config_name": {
                    "type": "string",
                    "description": "Name of the IP-ban config "
                                   "(see ip_ban_list_configs).",
                },
            },
            "required": ["config_name"],
        },
        "chat_exposed": True,
        "required_service": "ip_ban",
    },
    "ip_ban_set": {
        "description": (
            "Ban or unban an IP address via a named WAF/SecurityGroup/NACL "
            "config. Set action='ban' to block or action='unban' to remove "
            "the block. Mutates live traffic rules — confirm with the user "
            "first."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IPv4/IPv6 address to ban or unban.",
                },
                "config_name": {
                    "type": "string",
                    "description": "Name of the IP-ban config "
                                   "(see ip_ban_list_configs).",
                },
                "action": {
                    "type": "string",
                    "enum": ["ban", "unban"],
                    "description": "'ban' to block the IP, 'unban' to remove "
                                   "an existing block.",
                    "default": "ban",
                },
            },
            "required": ["ip_address", "config_name"],
        },
        "chat_exposed": True,
        "required_service": "ip_ban",
    },
}


def mcp_tool_list(
    have_ovh: bool = True,
    have_hetzner: bool = True,
    have_ip_ban: bool = True,
    have_memory: bool = True,
) -> list:
    """Build the list of ``mcp.types.Tool`` objects for the MCP server.

    Service-gated tools are dropped when the corresponding capability isn't
    available — agents querying ``tools/list`` get a clean view of what's
    actually callable. OVH and Hetzner are gated on the provider service
    being wired up; ``ip_ban`` is gated on at least one ban configuration
    existing (the service itself is always present); ``memory`` is gated on
    the memory subsystem being wired and enabled (``config.memory.enabled``).

    CloudWatch/CloudTrail tools are intentionally NOT gated — AWS is the base
    provider (like ``list_instances``), not an optional add-on. Session and
    relay tools are not gated either: login state can change mid-session, so
    they stay visible and return a clear "run `servonaut login`" error when
    unauthenticated.
    """
    from mcp.types import Tool
    gates = {
        'ovh': have_ovh,
        'hetzner': have_hetzner,
        'ip_ban': have_ip_ban,
        'memory': have_memory,
    }
    out = []
    for name, spec in TOOL_SCHEMAS.items():
        required = spec.get("required_service")
        if required and not gates.get(required, True):
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
