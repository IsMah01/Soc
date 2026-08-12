# Mini SOC Lab

A Docker-based SOC lab that combines Elastic Stack, TheHive, Cortex, MISP, Shuffle, and an AI-assisted SOC alert analysis worker. The project is built for local security monitoring demos, alert generation, Elastic-to-TheHive synchronization, enrichment with Cortex analyzers, and AI-generated investigation reports.

## Contents

- [Architecture](#architecture)
- [Main Services](#main-services)
- [Repository Layout](#repository-layout)
- [Requirements](#requirements)
- [Configuration](#configuration)
- [Quick Start](#quick-start)
- [Common Operations](#common-operations)
- [AI SOC Assistant](#ai-soc-assistant)
- [Detection and Test Data Scripts](#detection-and-test-data-scripts)
- [Generated Outputs](#generated-outputs)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)

## Architecture

The lab runs as one Docker Compose environment on the `soc-network` bridge network.

Typical flow:

1. Logs or test events are indexed into Elasticsearch.
2. Elastic Security rules create alerts.
3. `elastic-thehive-sync` polls Elastic alert indices and creates TheHive alerts.
4. TheHive stores and manages investigations.
5. Cortex runs analyzers against alert observables.
6. `ai-soc-automation` polls new TheHive alerts, collects observables and enrichment reports, selects a SOC playbook, sends the prompt to an LLM, writes a Markdown report, and comments back on the TheHive alert.

## Main Services

| Service | Purpose | Local URL / Port |
| --- | --- | --- |
| Elasticsearch | Search and alert data store | `http://localhost:9200` |
| Kibana | Elastic UI and detection rules | `http://localhost:5601` |
| Logstash | Log ingestion pipelines | `5044`, `5000`, `9600` |
| TheHive | Case and alert management | `http://localhost:9000` |
| Cortex | Analyzer and responder engine | `http://localhost:9001` |
| MinIO | Object storage used by TheHive | `http://localhost:9003` |
| Shuffle | SOAR automation platform | `http://localhost:3001` |
| MISP | Threat intelligence platform | `https://localhost:8443` |
| Portainer | Docker management UI | `http://localhost:9004` |
| elastic-thehive-sync | Elastic alert to TheHive sync worker | container only |
| ai-soc-automation | AI analysis and TheHive comment worker | container only |

## Repository Layout

```text
.
├── docker-compose.yml              # Full SOC lab stack
├── .env                            # Local runtime configuration and secrets
├── Dockerfile.sync                 # Elastic -> TheHive sync worker image
├── Dockerfile.ai-soc-assistant     # AI SOC automation worker image
├── sync.py                         # Elastic alert polling and TheHive alert creation
├── ai-soc-assistant/
│   ├── app.py                      # Manual AI alert analysis CLI
│   ├── auto_worker.py              # Automated TheHive/Cortex/LLM worker
│   ├── config.py                   # Environment-based configuration
│   ├── playbooks/                  # SOC playbook definitions
│   ├── prompts/                    # LLM prompt template
│   ├── rules/                      # Elastic detection rule JSON files
│   ├── samples/                    # Sample alert payloads
│   └── outputs/                    # Generated prompts and reports
├── scripts/
│   ├── send_ssh_bruteforce_logs.py
│   ├── inject_o365_mass_sharing_events.py
│   ├── upsert_o365_elastic_rule.py
│   └── create_direct_o365_signal_alert.py
├── elasticsearch/config/
├── kibana/config/
├── logstash/config/
├── logstash/pipeline/
├── thehive/config/
├── cortex/config/
├── cortex/analyzers/
├── misp/config/
├── rapport/                        # Project report sources and exported PDFs
└── prez/                           # Presentation sources and exported PDF
```

## Requirements

- Docker and Docker Compose
- Python 3.11+ for running local helper scripts
- Enough memory for Elastic, TheHive, Cortex, MISP, and Shuffle together
- Network access to pull Docker images on first startup
- An LLM API key for AI analysis

For local Python script usage:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r ai-soc-assistant/requirements.txt
```

## Configuration

The root `.env` file controls Docker Compose and worker settings. Keep it local and do not commit real secrets.

Important variables:

```text
ELASTIC_VERSION
ELASTIC_PASSWORD
ELASTIC_MEMORY
THEHIVE_VERSION
THEHIVE_SECRET
THEHIVE_API_KEY
LLM_PROVIDER
LLM_BASE_URL
LLM_MODEL
LLM_API_KEY
CORTEX_URL
CORTEX_API_KEY
AUTO_POLL_INTERVAL
AUTO_ALERT_RANGE
AUTO_ANALYZER_WAIT_SECONDS
AUTO_ANALYZER_POLL_SECONDS
AUTO_PROCESS_EXISTING
AUTO_ANALYZER_NAMES
CASSANDRA_VERSION
MINIO_ROOT_USER
MINIO_ROOT_PASSWORD
REDIS_PASSWORD
SHUFFLE_VERSION
SHUFFLE_OPENSEARCH_PASSWORD
NETWORK_SUBNET
TZ
```

The AI assistant also includes `ai-soc-assistant/.env.example` for standalone CLI runs.

## Quick Start

Start the full stack:

```bash
docker compose up -d --build
```

Check service status:

```bash
docker compose ps
```

Follow logs for the sync worker:

```bash
docker logs -f elastic-thehive-sync
```

Follow logs for the AI automation worker:

```bash
docker logs -f ai-soc-automation
```

Stop the stack:

```bash
docker compose down
```

Stop the stack and remove named volumes:

```bash
docker compose down -v
```

## Common Operations

Open the main UIs:

- Kibana: `http://localhost:5601`
- TheHive: `http://localhost:9000`
- Cortex: `http://localhost:9001`
- Shuffle: `http://localhost:3001`
- MISP: `https://localhost:8443`
- Portainer: `http://localhost:9004`

Rebuild only the AI automation worker:

```bash
docker compose build ai-soc-automation
docker compose up -d ai-soc-automation
```

Rebuild only the Elastic-to-TheHive sync worker:

```bash
docker compose build elastic-thehive-sync
docker compose up -d elastic-thehive-sync
```

## AI SOC Assistant

Manual sample analysis:

```bash
cd ai-soc-assistant
python app.py --sample samples/sample_sql_injection_alert.json
```

Show the prompt without calling the LLM:

```bash
cd ai-soc-assistant
python app.py --sample samples/sample_sql_injection_alert.json --show-prompt
```

Analyze a TheHive alert:

```bash
cd ai-soc-assistant
python app.py --alert-id '~123456789'
```

Analyze a TheHive alert and write the report back as a comment:

```bash
cd ai-soc-assistant
python app.py --alert-id '~123456789' --write-back
```

Run one automation cycle locally:

```bash
cd ai-soc-assistant
python auto_worker.py --once
```

The automated container runs `auto_worker.py` continuously by default.

## Detection and Test Data Scripts

Create or update the Office 365 mass sharing detection rule in Kibana:

```bash
python scripts/upsert_o365_elastic_rule.py --profile tuned
```

Push the before-tuning version of the same rule:

```bash
python scripts/upsert_o365_elastic_rule.py --profile before-tuning
```

Inject SSH brute force test logs:

```bash
python scripts/send_ssh_bruteforce_logs.py
```

Generate richer Mini SOC test events:

```bash
python mini_soc_alert_generator.py --help
```

Create a simple Elastic alert document:

```bash
python create_elastic_alerts.py
```

## Generated Outputs

The AI assistant writes generated prompts and reports to:

```text
ai-soc-assistant/outputs/
```

Typical files:

- `*_prompt.txt`
- `*_ai_report.md`
- `*_playbook_not_found.md`
- `automation_state.json`

The container mounts this directory so generated reports persist on the host.

## Security Notes

- This is a local lab project, not a production deployment.
- Rotate all default passwords, API keys, encryption keys, and MISP credentials before using it outside a private test machine.
- The compose stack mounts the Docker socket for Cortex, Shuffle, Portainer, and MISP initialization. Treat those containers as highly privileged.
- Do not commit `.env`, generated reports containing sensitive alert data, API tokens, or organization-specific threat intelligence.
- Several scripts use local default credentials for convenience. Replace them with environment variables or secret management before wider use.

## Troubleshooting

If Elasticsearch does not start, increase Docker memory and check:

```bash
docker logs elasticsearch
```

If Kibana cannot connect, verify Elasticsearch health:

```bash
curl -u elastic:$ELASTIC_PASSWORD http://localhost:9200/_cluster/health
```

If TheHive is not ready, check its dependencies:

```bash
docker compose ps cassandra minio thehive-redis elasticsearch thehive
```

If AI reports are not generated, check:

```bash
docker logs ai-soc-automation
```

Also verify:

- `LLM_API_KEY` is set.
- `THEHIVE_API_KEY` is valid.
- `CORTEX_API_KEY` is valid.
- New alerts have status `New`.
- Alerts are not already listed in `ai-soc-assistant/outputs/automation_state.json`.

If Elastic alerts are not appearing in TheHive, check:

```bash
docker logs elastic-thehive-sync
```

Also verify that Elastic alert indices match one of:

```text
.siem-signals-default-*
.alerts-security.alerts-*
```
