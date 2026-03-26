from fastapi import APIRouter, Header, HTTPException
from .settings import settings
from .models import WebhookEvent
from .sync import sync_reservations

router = APIRouter()

@router.post("/webhook")
async def webhook(event: WebhookEvent, x_hook_signature: str = Header(None)):
    if x_hook_signature != settings.webhook_secret:
        raise HTTPException(status_code=401, detail="Invalid signature")

    if event.model in ["ipaddress", "prefix"]:
        await sync_reservations()

    return {"status": "ok"}
