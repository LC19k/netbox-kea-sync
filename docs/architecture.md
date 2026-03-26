# NetBox → Kea Sync Service Architecture

This service listens for NetBox webhooks and updates Kea DHCP reservations accordingly.

- NetBox is authoritative for reservations.
- Kea is authoritative for leases.
- Sync is triggered by webhook events or manual `/sync-now`.
