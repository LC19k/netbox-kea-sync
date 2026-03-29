import os
import yaml
from pathlib import Path

class Settings:
    def __init__(self):
        config_path = Path("/app/config/settings.yaml")

        if config_path.exists():
            data = yaml.safe_load(config_path.read_text())
        else:
            data = {}

        # Helper to safely read nested YAML keys
        def get(path, default=None):
            node = data
            for key in path.split("."):
                if not isinstance(node, dict) or key not in node:
                    return default
                node = node[key]
            return node

        # ------------------------------------------------------------
        # ENVIRONMENT OVERRIDES CONFIG FILE
        # ------------------------------------------------------------
        self.netbox_url = (
            os.getenv("NETBOX_URL")
            or get("netbox.url")
            or "http://netbox:8000"
        )

        self.netbox_token = (
            os.getenv("NETBOX_TOKEN")
            or get("netbox.token")
            or ""
        )

        self.kea_url = (
            os.getenv("KEA_URL")
            or get("kea.url")
            or "http://kea-ctrl-agent:8000"
        )

        self.webhook_secret = (
            os.getenv("WEBHOOK_SECRET")
            or get("webhook.secret")
            or ""
        )

        # ------------------------------------------------------------
        # STARTUP DEBUG PRINT
        # ------------------------------------------------------------
        print("=== STARTUP SECRET CHECK ===")
        print(f"WEBHOOK_SECRET (len={len(self.webhook_secret)}): {repr(self.webhook_secret)}")
        print("=== END SECRET CHECK ===")

settings = Settings()
