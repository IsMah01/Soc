import requests


class TheHiveClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    def get_alert(self, alert_id: str) -> dict:
        """
        Retrieve one alert from TheHive.
        """

        url = f"{self.base_url}/api/v1/alert/{alert_id}"

        response = requests.get(
            url,
            headers=self.headers,
            timeout=20
        )

        if response.status_code != 200:
            raise Exception(
                f"Failed to retrieve alert {alert_id}: "
                f"{response.status_code} - {response.text}"
            )

        return response.json()

    def list_alerts(self, alert_range: str = "0-20") -> list[dict]:
        """
        List alerts from TheHive using the query API.
        """

        url = f"{self.base_url}/api/v1/query"
        payload = {
            "query": [
                {
                    "_name": "listAlert"
                }
            ],
            "range": alert_range
        }

        response = requests.post(
            url,
            headers=self.headers,
            json=payload,
            timeout=20
        )

        if response.status_code != 200:
            raise Exception(
                "Failed to list alerts: "
                f"{response.status_code} - {response.text}"
            )

        alerts = response.json()
        if isinstance(alerts, list):
            return alerts

        return []

    def get_alert_observables(self, alert_id: str) -> list[dict]:
        """
        Retrieve observables attached to one alert.
        """

        url = f"{self.base_url}/api/v1/query"
        payload = {
            "query": [
                {
                    "_name": "getAlert",
                    "idOrName": alert_id
                },
                {
                    "_name": "observables"
                }
            ]
        }

        response = requests.post(
            url,
            headers=self.headers,
            json=payload,
            timeout=20
        )

        if response.status_code != 200:
            raise Exception(
                f"Failed to retrieve observables for alert {alert_id}: "
                f"{response.status_code} - {response.text}"
            )

        observables = response.json()
        if isinstance(observables, list):
            return observables

        return []

    def list_cortex_analyzers(self) -> list[dict]:
        """
        List Cortex analyzers exposed through TheHive.
        """

        url = f"{self.base_url}/api/connector/cortex/analyzer"

        response = requests.get(
            url,
            headers=self.headers,
            timeout=20
        )

        if response.status_code != 200:
            raise Exception(
                "Failed to list Cortex analyzers from TheHive: "
                f"{response.status_code} - {response.text}"
            )

        analyzers = response.json()
        if isinstance(analyzers, list):
            return analyzers

        return []

    def run_cortex_analyzer(
        self,
        observable_id: str,
        analyzer_id: str,
        cortex_id: str = "local"
    ) -> dict:
        """
        Launch one Cortex analyzer job through TheHive.
        """

        url = f"{self.base_url}/api/connector/cortex/job"
        payload = {
            "cortexId": cortex_id,
            "artifactId": observable_id,
            "analyzerId": analyzer_id
        }

        response = requests.post(
            url,
            headers=self.headers,
            json=payload,
            timeout=20
        )

        if response.status_code not in [200, 201]:
            raise Exception(
                f"Failed to run analyzer {analyzer_id} on {observable_id}: "
                f"{response.status_code} - {response.text}"
            )

        return response.json()

    def get_cortex_job(self, job_id: str) -> dict:
        url = f"{self.base_url}/api/connector/cortex/job/{job_id}"

        response = requests.get(
            url,
            headers=self.headers,
            timeout=20
        )

        if response.status_code != 200:
            raise Exception(
                f"Failed to retrieve TheHive Cortex job {job_id}: "
                f"{response.status_code} - {response.text}"
            )

        return response.json()

    def add_alert_comment(self, alert_id: str, comment: str) -> dict:
        """
        Add AI analysis report as a comment in TheHive.
        """

        url = f"{self.base_url}/api/v1/alert/{alert_id}/comment"

        payload = {
            "message": comment
        }

        response = requests.post(
            url,
            headers=self.headers,
            json=payload,
            timeout=20
        )

        if response.status_code not in [200, 201]:
            raise Exception(
                f"Failed to add comment to alert {alert_id}: "
                f"{response.status_code} - {response.text}"
            )

        return response.json()
