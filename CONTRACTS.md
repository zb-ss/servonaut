# CONTRACTS.md — OVH Full Features Interface Contracts

All interfaces between components for the OVH Full Features epic.
Each component can be developed and tested independently against these contracts.

---

## 1. Service Constructor Pattern

All new OVH services follow the `OVHBillingService` pattern:

```python
class OVH<Domain>Service:
    """<Domain> operations via OVHcloud API."""

    def __init__(self, ovh_service: 'OVHService') -> None:
        self._ovh_service = ovh_service

    # Access the shared client via:
    #   client = self._ovh_service.client
    # All blocking OVH API calls MUST use asyncio.to_thread().
```

---

## 2. ConfirmActionScreen

**File**: `src/servonaut/screens/confirm_action.py`

```python
from textual.screen import Screen

class ConfirmActionScreen(Screen):
    """Reusable modal for confirming destructive operations.

    Returns True (confirmed) or False (cancelled) via self.dismiss().
    Usage: confirmed = await self.app.push_screen_wait(ConfirmActionScreen(...))
    """

    def __init__(
        self,
        title: str,                # e.g. "Reinstall VPS"
        description: str,          # Rich markup explanation
        consequences: List[str],   # bullet list shown in red/warning
        confirm_text: str,         # exact text user must type (case-sensitive)
        action_label: str,         # confirm button label
        severity: str = "danger",  # "danger" (red) | "warning" (amber)
    ) -> None: ...
```

**Behavior contract**:
- Confirm button DISABLED until Input.value == confirm_text (case-sensitive)
- Button variant: `error` for danger, `warning` for warning severity
- Escape always cancels (dismiss(False))
- Input auto-focuses on mount

---

## 3. OVH Audit Logger

**File**: `src/servonaut/services/ovh_audit.py`

```python
class OVHAuditLogger:
    """Append-only JSON-lines audit log for destructive OVH operations."""

    def __init__(self, audit_path: str = "~/.servonaut/ovh_audit.json") -> None: ...

    def log_action(
        self,
        action: str,       # e.g. "vps_reinstall", "cloud_delete"
        target: str,       # e.g. "vps-abc123.ovh.net"
        details: dict,     # action-specific (image_id, template, etc.)
        confirmed: bool,   # whether user confirmed
    ) -> None:
        """Append entry: {ts, action, target, details, confirmed}."""
```

---

## 4. OVHVPSService

**File**: `src/servonaut/services/ovh_vps_service.py`

```python
class OVHVPSService:
    def __init__(self, ovh_service: 'OVHService') -> None: ...

    async def list_images(self, vps_name: str) -> List[dict]:
        """GET /vps/{serviceName}/availableImages -> [{id, name, os_type}]"""

    async def reinstall(self, vps_name: str, image_id: str) -> bool:
        """POST /vps/{serviceName}/reinstall {imageId}"""

    async def list_upgrade_models(self, vps_name: str) -> List[dict]:
        """GET /vps/{serviceName}/availableUpgrade -> [{name, vcpus, ram, disk, price}]"""

    async def upgrade(self, vps_name: str, model: str) -> bool:
        """POST /vps/{serviceName}/change or order endpoint"""
```

---

## 5. OVHDedicatedService

**File**: `src/servonaut/services/ovh_dedicated_service.py`

```python
class OVHDedicatedService:
    def __init__(self, ovh_service: 'OVHService') -> None: ...

    async def list_templates(self, server_name: str) -> List[dict]:
        """GET /dedicated/server/{sn}/install/compatibleTemplates"""

    async def get_template_details(self, template_name: str) -> dict:
        """GET /dedicated/installationTemplate/{templateName}"""

    async def reinstall(
        self, server_name: str, template_name: str,
        customization: Optional[dict] = None,
    ) -> dict:
        """POST /dedicated/server/{sn}/install/start -> task dict"""

    async def get_install_status(self, server_name: str) -> dict:
        """GET /dedicated/server/{sn}/install/status"""
```

---

## 6. OVHCloudService

**File**: `src/servonaut/services/ovh_cloud_service.py`

```python
class OVHCloudService:
    def __init__(self, ovh_service: 'OVHService') -> None: ...

    async def list_flavors(self, project_id: str, region: str = "") -> List[dict]: ...
    async def list_images(self, project_id: str, region: str = "") -> List[dict]: ...
    async def list_ssh_keys(self, project_id: str) -> List[dict]: ...
    async def add_ssh_key(self, project_id: str, name: str, public_key: str, region: str = "") -> dict: ...
    async def delete_ssh_key(self, project_id: str, key_id: str) -> bool: ...
    async def create_instance(self, project_id: str, name: str, flavor_id: str, image_id: str, region: str, ssh_key_id: str = "") -> dict: ...
    async def delete_instance(self, project_id: str, instance_id: str) -> bool: ...
    async def resize_instance(self, project_id: str, instance_id: str, flavor_id: str) -> dict: ...
```

---

## 7. OVHMonitoringService

**File**: `src/servonaut/services/ovh_monitoring_service.py`

```python
class OVHMonitoringService:
    def __init__(self, ovh_service: 'OVHService') -> None: ...

    async def get_vps_monitoring(self, vps_name: str, period: str = "lastday") -> dict: ...
    async def get_dedicated_monitoring(self, server_name: str, period: str = "lastday") -> dict: ...
    async def get_cloud_monitoring(self, project_id: str, instance_id: str, period: str = "lastday") -> dict: ...
```

---

## 8. OVHIPService

**File**: `src/servonaut/services/ovh_ip_service.py`

```python
class OVHIPService:
    def __init__(self, ovh_service: 'OVHService') -> None: ...

    # IP Management
    async def list_ips(self) -> List[dict]: ...
    async def list_failover_ips(self) -> List[dict]: ...
    async def move_failover_ip(self, ip: str, target_service: str) -> bool: ...
    async def get_ip_details(self, ip: str) -> dict: ...

    # Reverse DNS
    async def get_reverse_dns(self, ip_block: str, ip: str) -> dict: ...
    async def set_reverse_dns(self, ip_block: str, ip: str, reverse: str) -> bool: ...
    async def delete_reverse_dns(self, ip_block: str, ip: str) -> bool: ...

    # Firewall
    async def get_firewall(self, ip: str) -> dict: ...
    async def toggle_firewall(self, ip: str, enabled: bool) -> bool: ...
    async def list_firewall_rules(self, ip: str) -> List[dict]: ...
    async def add_firewall_rule(self, ip: str, rule: dict) -> dict: ...
    async def delete_firewall_rule(self, ip: str, sequence: int) -> bool: ...
```

---

## 9. OVHSnapshotService

**File**: `src/servonaut/services/ovh_snapshot_service.py`

```python
class OVHSnapshotService:
    def __init__(self, ovh_service: 'OVHService') -> None: ...

    # VPS Snapshots
    async def list_vps_snapshots(self, vps_name: str) -> List[dict]: ...
    async def create_vps_snapshot(self, vps_name: str, description: str = "") -> dict: ...
    async def restore_vps_snapshot(self, vps_name: str, snapshot_id: str) -> bool: ...
    async def delete_vps_snapshot(self, vps_name: str) -> bool: ...

    # VPS Automated Backups
    async def get_vps_backup_options(self, vps_name: str) -> dict: ...
    async def configure_vps_backup(self, vps_name: str, schedule: str) -> bool: ...
    async def list_vps_backups(self, vps_name: str) -> List[dict]: ...
    async def restore_vps_backup(self, vps_name: str, restore_point: str) -> bool: ...

    # Cloud Snapshots
    async def list_cloud_snapshots(self, project_id: str) -> List[dict]: ...
    async def create_cloud_snapshot(self, project_id: str, instance_id: str, snapshot_name: str) -> dict: ...
    async def delete_cloud_snapshot(self, project_id: str, snapshot_id: str) -> bool: ...
```

---

## 10. OVHStorageService

**File**: `src/servonaut/services/ovh_storage_service.py`

```python
class OVHStorageService:
    def __init__(self, ovh_service: 'OVHService') -> None: ...

    async def list_volumes(self, project_id: str) -> List[dict]: ...
    async def create_volume(self, project_id: str, name: str, size_gb: int, region: str, volume_type: str = "classic") -> dict: ...
    async def delete_volume(self, project_id: str, volume_id: str) -> bool: ...
    async def attach_volume(self, project_id: str, volume_id: str, instance_id: str) -> dict: ...
    async def detach_volume(self, project_id: str, volume_id: str, instance_id: str) -> dict: ...
    async def create_volume_snapshot(self, project_id: str, volume_id: str, name: str) -> dict: ...
```

---

## 11. OVHDNSService

**File**: `src/servonaut/services/ovh_dns_service.py`

```python
class OVHDNSService:
    def __init__(self, ovh_service: 'OVHService') -> None: ...

    async def list_domains(self) -> List[str]: ...
    async def get_zone_info(self, zone_name: str) -> dict: ...
    async def list_records(self, zone_name: str, field_type: str = "", sub_domain: str = "") -> List[dict]: ...
    async def create_record(self, zone_name: str, field_type: str, sub_domain: str, target: str, ttl: int = 3600) -> dict: ...
    async def update_record(self, zone_name: str, record_id: int, sub_domain: Optional[str] = None, target: Optional[str] = None, ttl: Optional[int] = None) -> bool: ...
    async def delete_record(self, zone_name: str, record_id: int) -> bool: ...
    async def refresh_zone(self, zone_name: str) -> bool: ...
    async def get_domain_info(self, domain: str) -> dict: ...
    async def list_domain_tasks(self, domain: str) -> List[dict]: ...
```

---

## 12. OVHBillingService (Enhanced)

**File**: `src/servonaut/services/ovh_billing_service.py` (existing, extended)

New methods added to existing class:

```python
async def get_service_list(self) -> List[dict]: ...
async def get_service_details(self, service_id: str) -> dict: ...
async def get_invoice_details(self, bill_id: str) -> dict: ...
async def get_invoice_pdf_url(self, bill_id: str) -> str: ...
async def get_monthly_spend_history(self, months: int = 6) -> List[dict]: ...
async def get_cloud_cost_forecast(self, project_id: str) -> dict: ...
```

---

## 13. Config Schema Extensions

New fields on `OVHConfig` (all with defaults, no migration required):

```python
ovh_audit_path: str = "~/.servonaut/ovh_audit.json"
cost_alert_threshold: float = 0.0   # monthly threshold, 0 = disabled
cost_alert_currency: str = "EUR"
```

---

## 14. App Service Attributes

New attributes on `ServonautApp` (all default to `None`):

```python
ovh_vps_service = None         # OVHVPSService
ovh_dedicated_service = None   # OVHDedicatedService
ovh_cloud_service = None       # OVHCloudService
ovh_monitoring_service = None  # OVHMonitoringService
ovh_ip_service = None          # OVHIPService
ovh_snapshot_service = None    # OVHSnapshotService
ovh_storage_service = None     # OVHStorageService
ovh_dns_service = None         # OVHDNSService
ovh_audit = None               # OVHAuditLogger
```

---

## 15. Screen File Inventory

| Screen Class | File | Constructor | Pushed From |
|---|---|---|---|
| `ConfirmActionScreen` | `screens/confirm_action.py` | See contract #2 | Any screen (modal) |
| `OVHReinstallScreen` | `screens/ovh_reinstall.py` | `(instance: dict)` | ServerActionsScreen |
| `OVHResizeScreen` | `screens/ovh_resize.py` | `(instance: dict)` | ServerActionsScreen |
| `OVHCloudCreateScreen` | `screens/ovh_cloud_create.py` | `()` | Sidebar nav |
| `OVHMonitoringScreen` | `screens/ovh_monitoring.py` | `(instance: dict)` | ServerActionsScreen |
| `OVHIPManagementScreen` | `screens/ovh_ip_management.py` | `()` | Sidebar nav |
| `OVHFirewallScreen` | `screens/ovh_firewall.py` | `(instance: dict)` | ServerActionsScreen |
| `OVHSnapshotsScreen` | `screens/ovh_snapshots.py` | `(instance: dict)` | ServerActionsScreen |
| `OVHStorageScreen` | `screens/ovh_storage.py` | `()` | Sidebar nav |
| `OVHDNSScreen` | `screens/ovh_dns.py` | `()` | Sidebar nav |
| `OVHBillingScreen` | `screens/ovh_billing.py` | `()` | Sidebar nav |

---

## 16. Sidebar Navigation IDs

```python
"OVHDNSScreen":            "nav_ovh_dns"
"OVHIPManagementScreen":   "nav_ovh_ips"
"OVHStorageScreen":        "nav_ovh_storage"
"OVHBillingScreen":        "nav_ovh_billing"
"OVHCloudCreateScreen":    "nav_ovh_cloud_new"
```

---

## 17. MCP Tool Contracts (CLI, Read-Only)

All new tools are guard level `readonly`. Added to `ServonautTools`:

```python
async def ovh_monitoring(self, instance_id: str, period: str = "lastday") -> str: ...
async def ovh_list_ips(self) -> str: ...
async def ovh_firewall_rules(self, ip: str) -> str: ...
async def ovh_ssh_keys(self) -> str: ...
async def ovh_snapshots(self, instance_id: str) -> str: ...
async def ovh_dns_records(self, zone: str, record_type: str = "") -> str: ...
async def ovh_billing(self) -> str: ...
async def ovh_invoices(self, limit: int = 5) -> str: ...
```

---

## 18. Backend Relay Contracts (servonaut.dev)

Destructive tools relayed via `ProxiedToolHandler`: `ovh_reinstall`, `ovh_resize`,
`ovh_create_instance`, `ovh_delete_instance`, `ovh_snapshot_create`, `ovh_snapshot_restore`,
`ovh_snapshot_delete`, `ovh_move_ip`, `ovh_set_reverse_dns`, `ovh_firewall_modify`,
`ovh_dns_modify`, `ovh_volume_manage`.

New entitlement: `ovh_mcp_operations` (Free: 0, Solo: 50/day, Teams: 200/day per seat).

---

## 19. Consumer Key Access Rules (Complete)

All required OVH API permissions — collected into `request_consumer_key()` by the integration component. See the plan org file for the full list.
