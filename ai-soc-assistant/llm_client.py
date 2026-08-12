import json
import requests
from config import Config


class LLMClient:
    def __init__(self):
        self.provider = Config.LLM_PROVIDER.lower()
        self.model = Config.LLM_MODEL

        if self.provider == "openai":
            try:
                from openai import OpenAI
            except ImportError as error:
                raise RuntimeError(
                    "The openai package is not installed. "
                    "Install ai-soc-assistant/requirements.txt before running LLM analysis."
                ) from error

            self.client = OpenAI(api_key=Config.LLM_API_KEY)
        elif self.provider == "openrouter":
            self.base_url = (
                Config.LLM_BASE_URL
                or "https://openrouter.ai/api/v1"
            ).rstrip("/")
            self.client = None
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

    def analyze_alert(self, prompt: str) -> dict:
        """
        Send alert + playbook to LLM and return JSON analysis.
        """

        if self.provider == "openrouter":
            return self._analyze_alert_openrouter(prompt)

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert SOC analyst. "
                        "You analyze security alerts using SOC playbooks. "
                        "You must return valid JSON only."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2,
            response_format={"type": "json_object"}
        )

        content = response.choices[0].message.content.strip()

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {
                "status": "generation_failed",
                "classification": "Unknown",
                "confidence": 0,
                "severity_recommendation": "Unknown",
                "summary": "The analysis report could not be generated because the LLM response was not valid JSON.",
                "evidence": [],
                "recommended_actions": [],
                "playbook_used": "Unknown",
                "limitations": [
                    "Technical generation failure: invalid JSON returned by the LLM."
                ]
            }

    def _analyze_alert_openrouter(self, prompt: str) -> dict:
        response = requests.post(
            f"{self.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {Config.LLM_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost",
                "X-Title": "AI SOC Assistant",
            },
            json={
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are an expert SOC analyst. "
                            "You analyze security alerts using SOC playbooks. "
                            "You must return valid JSON only."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.2,
                "response_format": {
                    "type": "json_object"
                }
            },
            timeout=90
        )

        if response.status_code != 200:
            raise RuntimeError(
                "OpenRouter request failed: "
                f"{response.status_code} - {response.text}"
            )

        payload = response.json()
        content = payload["choices"][0]["message"]["content"].strip()

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {
                "status": "generation_failed",
                "classification": "Unknown",
                "confidence": 0,
                "severity_recommendation": "Unknown",
                "summary": "The analysis report could not be generated because the LLM response was not valid JSON.",
                "evidence": [],
                "recommended_actions": [],
                "playbook_used": "Unknown",
                "limitations": [
                    "Technical generation failure: invalid JSON returned by the LLM."
                ]
            }
