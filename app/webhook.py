from fastapi import APIRouter, Header, HTTPException, Request
import hashlib
import hmac
import os

from .settings import settings
from .models import WebhookEvent
from .sync import sync_reservations

router = APIRouter()

# Optional debug toggle (set WEBHOOK_DEBUG=1 in env to enable hex dump)
DEBUG = os.getenv("WEBHOOK_DEBUG", "0") == "1"


@router.post("/webhook")
async def webhook(
    request: Request,
    x_hook_signature: str = Header(None, alias="X-Hook-Signature"),
    x_webhook_signature: str = Header(None, alias="X-Webhook-Signature"),
):
    headers = dict(request.headers)
    print("HEADERS:", headers)

    raw_body = await request.body()

    if DEBUG:
        print("RAW BODY HEX:", raw_body.hex())

    # ------------------------------------------------------------
    # MODE A: Legacy / NetBox CE style
    # Header: X-Hook-Signature
    # Value: sha512(body)
    # ------------------------------------------------------------
    if x_hook_signature:
        expected = hashlib.sha512(raw_body).hexdigest()
        if not hmac.compare_digest(x_hook_signature, expected):
            raise HTTPException(status_code=401, detail="Invalid legacy signature")
        return await handle_event(request)

    # ------------------------------------------------------------
    # MODE B: Modern HMAC mode (NetBox 4.x+)
    # Header: X-Webhook-Signature
    # Value: sha256=<hmac(secret, body)>
    # ------------------------------------------------------------
    if x_webhook_signature:
        if not x_webhook_signature.startswith("sha256="):
            raise HTTPException(status_code=401, detail="Invalid signature format")

        sent = x_webhook_signature.split("=", 1)[1]

        expected = hmac.new(
            key=settings.webhook_secret.encode(),
            msg=raw_body,
            digestmod=hashlib.sha256,
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
    data = await request.json()
    event = WebhookEvent(**data)

    if event.object_type in ["ipam.ipaddress", "ipam.prefix"]:
        await sync_reservations()

    return {"status": "ok"}
