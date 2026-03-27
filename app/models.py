from pydantic import BaseModel
from typing import Optional, Dict, Any

class WebhookEvent(BaseModel):
    event: str
    object_type: str
    timestamp: Optional[str] = None
    username: Optional[str] = None
    request_id: Optional[str] = None
    data: Dict[str, Any]
    snapshots: Optional[Dict[str, Any]] = None
