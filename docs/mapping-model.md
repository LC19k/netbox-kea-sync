# Mapping Model

NetBox IP addresses with role=dhcp map to Kea reservations.

Fields:
- NetBox `address` → Kea `ip-address`
- NetBox `mac_address` → Kea `hw-address`
- NetBox `description` → Kea `hostname`
