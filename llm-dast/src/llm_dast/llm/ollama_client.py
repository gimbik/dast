import httpx
import json
import logging
from tenacity import retry, stop_after_attempt, wait_exponential

log = logging.getLogger(__name__)

class OllamaClient:
    def __init__(self, base_url: str, model: str, temperature: float = 0.1, json_mode: bool = True):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.json_mode = json_mode
        self.client = httpx.Client(timeout=120.0)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=2, max=30))
    def chat(self, system: str, user: str) -> dict:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_ctx": 8192
            },
        }
        
        if self.json_mode:
            payload["format"] = "json"

        resp = self.client.post(f"{self.base_url}/api/chat", json=payload)
        resp.raise_for_status()
        content = resp.json()["message"]["content"]
        
        if self.json_mode:
            return json.loads(content)
        return content