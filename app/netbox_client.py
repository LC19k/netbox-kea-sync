import httpx
from .settings import settings

class NetBoxClient:
    def __init__(self):
        self.client = httpx.AsyncClient(
            base_url=settings.netbox_url,
            headers={"Authorization": f"Token {settings.netbox_token}"}
        )

    async def get_reservations(self):
        r = await self.client.get("/api/ipam/ip-addresses/?role=dhcp")
        r.raise_for_status()
        return r.json()["results"]

netbox = NetBoxClient()
