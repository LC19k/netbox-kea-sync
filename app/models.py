from pydantic import BaseModel

class WebhookEvent(BaseModel):
    event: str
    model: str
    data: dict
