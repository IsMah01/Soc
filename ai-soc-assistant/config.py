import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000")
    THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")

    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai")
    LLM_API_KEY = os.getenv("LLM_API_KEY", "")
    LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")
    LLM_BASE_URL = os.getenv("LLM_BASE_URL", "")

    OUTPUT_DIR = os.getenv("OUTPUT_DIR", "outputs")

    CORTEX_URL = os.getenv("CORTEX_URL", "http://localhost:9001")
    CORTEX_API_KEY = os.getenv("CORTEX_API_KEY", "")

    AUTO_STATE_FILE = os.getenv("AUTO_STATE_FILE", "outputs/automation_state.json")
    AUTO_POLL_INTERVAL = int(os.getenv("AUTO_POLL_INTERVAL", "60"))
    AUTO_ALERT_RANGE = os.getenv("AUTO_ALERT_RANGE", "0-20")
    AUTO_ANALYZER_WAIT_SECONDS = int(os.getenv("AUTO_ANALYZER_WAIT_SECONDS", "120"))
    AUTO_ANALYZER_POLL_SECONDS = int(os.getenv("AUTO_ANALYZER_POLL_SECONDS", "5"))
    AUTO_PROCESS_EXISTING = os.getenv("AUTO_PROCESS_EXISTING", "false").lower() == "true"
    AUTO_ANALYZER_NAMES = os.getenv(
        "AUTO_ANALYZER_NAMES",
        (
            "AbuseIPDB_2_0,"
            "Abuse_Finder_3_0,"
            "EmailRep_1_0,"
            "GoogleSafebrowsing_2_0,"
            "MaxMind_GeoIP_4_0,"
            "VirusTotal_GetReport_3_1"
        )
    )

    @staticmethod
    def validate(require_llm: bool = True, require_thehive: bool = False):
        if require_llm and not Config.LLM_API_KEY:
            raise ValueError("LLM_API_KEY is required unless you use --show-prompt.")

        if require_thehive and not Config.THEHIVE_API_KEY:
            raise ValueError("THEHIVE_API_KEY is required when using --alert-id.")

    @staticmethod
    def auto_analyzer_names() -> set[str]:
        return {
            name.strip()
            for name in Config.AUTO_ANALYZER_NAMES.split(",")
            if name.strip()
        }
