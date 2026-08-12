import requests


class CortexClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    def get_job_report(self, cortex_job_id: str) -> dict:
        url = f"{self.base_url}/api/job/{cortex_job_id}/report"

        response = requests.get(
            url,
            headers=self.headers,
            timeout=20
        )

        if response.status_code != 200:
            raise Exception(
                f"Failed to retrieve Cortex job report {cortex_job_id}: "
                f"{response.status_code} - {response.text}"
            )

        return response.json()
