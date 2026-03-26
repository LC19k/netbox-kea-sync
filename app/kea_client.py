import httpx
from .settings import settings

class KeaClient:
    def __init__(self):
        self.client = httpx.AsyncClient(base_url=settings.kea_url)

    async def get_leases(self):
        payload = {"command": "lease4-get-all", "service": ["dhcp4"]}
        r = await self.client.post("/", json=payload)
        r.raise_for_status()
        return r.json()

    async def add_reservation(self, reservation):
        payload = {
            "command": "reservation-add",
            "service": ["dhcp4"],
            "arguments": reservation
        }
        await self.client.post("/", json=payload)

kea = KeaClient()
