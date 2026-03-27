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
    x_hook_signature: str = Header(None, alias="X-Hook-Signature")
):
    print("HEADERS:", dict(request.headers))

    raw_body = await request.body()

    if not x_hook_signature:
        raise HTTPException(status_code=401, detail="Missing signature header")

    # NetBox CE (Docker 4.0.2) uses SHA-512(body)
    expected_digest = hashlib.sha512(raw_body).hexdigest()

    if not hmac.compare_digest(x_hook_signature, expected_digest):
        raise HTTPException(status_code=401, detail="Invalid signature")

    event = WebhookEvent(**(await request.json()))

    if event.object_type in ["ipam.ipaddress", "ipam.prefix"]:
        await sync_reservations()

    return {"status": "ok"}
