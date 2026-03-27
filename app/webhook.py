from fastapi import APIRouter, Header, HTTPException, Request
import hmac
import hashlib

from .settings import settings
from .models import WebhookEvent
from .sync import sync_reservations

router = APIRouter()

@router.post("/webhook")
async def webhook(
    request: Request,
    x_hook_signature: str = Header(None)
):
    raw_body = await request.body()

    # NetBox sends: sha256=<digest>
    if not x_hook_signature or not x_hook_signature.startswith("sha256="):
        raise HTTPException(status_code=401, detail="Invalid signature format")

    sent_digest = x_hook_signature.split("=", 1)[1]

    expected_digest = hmac.new(
        key=settings.webhook_secret.encode(),
        msg=raw_body,
        digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(sent_digest, expected_digest):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse the event AFTER signature validation
    event = WebhookEvent(**(await request.json()))

    if event.object_type in ["ipam.ipaddress", "ipam.prefix"]:
        await sync_reservations()

    return {"status": "ok"}
