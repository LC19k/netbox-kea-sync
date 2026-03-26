import yaml
from pathlib import Path

class Settings:
    def __init__(self):
        config_path = Path("/app/config/settings.yaml")
        data = yaml.safe_load(config_path.read_text())

        self.netbox_url = data["netbox"]["url"]
        self.netbox_token = data["netbox"]["token"]

        self.kea_url = data["kea"]["url"]
        self.webhook_secret = data["webhook"]["secret"]

settings = Settings()
