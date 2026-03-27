from fastapi import APIRouter, Header, HTTPException, Request
import hashlib
import hmac

from .settings import settings
from .models import WebhookEvent
from .sync import sync_reservations

router = APIRouter()

@router.post("/webhook")
async def webhook(
    request: Request,
    x_hook_signature: str = Header(None, alias="X-Hook-Signature"),
    x_webhook_signature: str = Header(None, alias="X-Webhook-Signature")
):
    print("HEADERS:", dict(request.headers))

    raw_body = await request.body()

    # ------------------------------------------------------------
    # MODE A: NetBox CE / Legacy Mode
    # Header: X-Hook-Signature
    # Value: sha512(body)
    # ------------------------------------------------------------
    if x_hook_signature:
        expected = hashlib.sha512(raw_body).hexdigest()
        if not hmac.compare_digest(x_hook_signature, expected):
            raise HTTPException(status_code=401, detail="Invalid legacy signature")
        return await handle_event(request)

    # ------------------------------------------------------------
    # MODE B: NetBox 4.x Modern HMAC Mode
    # Header: X-Webhook-Signature
    # Value: sha256=<hmac>
    # ------------------------------------------------------------
    if x_webhook_signature:
        if not x_webhook_signature.startswith("sha256="):
            raise HTTPException(status_code=401, detail="Invalid signature format")

        sent = x_webhook_signature.split("=", 1)[1]

        expected = hmac.new(
            key=settings.webhook_secret.encode(),
            msg=raw_body,
            digestmod=hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(sent, expected):
            raise HTTPException(status_code=401, detail="Invalid HMAC signature")

        return await handle_event(request)

    # ------------------------------------------------------------
    # MODE C: No signature at all
    # ------------------------------------------------------------
    raise HTTPException(status_code=401, detail="Missing signature header")


async def handle_event(request: Request):
    """Shared event handler after signature validation."""
    event = WebhookEvent(**(await request.json()))

    if event.object_type in ["ipam.ipaddress", "ipam.prefix"]:
        await sync_reservations()

    return {"status": "ok"}
