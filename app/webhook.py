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
    x_hook_signature: str = Header(None, alias="X-Hook-Signature")
):
    print("HEADERS:", dict(request.headers))

    raw_body = await request.body()

    # NetBox sends: X-Hook-Signature: <digest>
    if not x_hook_signature:
        raise HTTPException(status_code=401, detail="Missing signature header")

    sent_digest = x_hook_signature

    expected_digest = hmac.new(
        key=settings.webhook_secret.encode(),
        msg=raw_body,
        digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(sent_digest, expected_digest):
        raise HTTPException(status_code=401, detail="Invalid signature")

    event = WebhookEvent(**(await request.json()))

    if event.object_type in ["ipam.ipaddress", "ipam.prefix"]:
        await sync_reservations()

    return {"status": "ok"}
