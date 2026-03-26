from .netbox_client import netbox
from .kea_client import kea

async def sync_reservations():
    nb_reservations = await netbox.get_reservations()
    kea_leases = await kea.get_leases()

    nb_ips = {r["address"] for r in nb_reservations}
    kea_ips = {l["ip-address"] for l in kea_leases.get("arguments", {}).get("leases", [])}

    missing = nb_ips - kea_ips

    for ip in missing:
        r = next(x for x in nb_reservations if x["address"] == ip)
        reservation = {
            "ip-address": r["address"],
            "hw-address": r["mac_address"],
            "hostname": r["description"] or "netbox-reservation"
        }
        await kea.add_reservation(reservation)
