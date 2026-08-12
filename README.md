# SOC Lab Platform

Local SOC lab based on Docker Compose. It combines Elastic Stack, TheHive, Cortex, MISP, Shuffle, and an AI SOC assistant that can analyze alerts and write investigation reports back to TheHive.

## Overview

This project is designed for security monitoring demos, alert investigation, threat intelligence enrichment, and SOC automation testing.

Main workflow:

1. Logs or simulated events are sent to Elasticsearch.
2. Elastic/Kibana detection rules generate alerts.
3. `elastic-thehive-sync` reads Elastic alerts and creates TheHive alerts.
4. Cortex analyzers enrich observables such as IPs, URLs, domains, and hostnames.
5. `ai-soc-automation` collects the alert, observables, and enrichment results.
6. The AI assistant selects the right playbook, generates a SOC report, and adds it as a TheHive comment.

## Stack

| Component | Role | URL / Port |
| --- | --- | --- |
| Elasticsearch | Event and alert storage | `http://localhost:9200` |
| Kibana | Elastic UI and detection rules | `http://localhost:5601` |
| Logstash | Log ingestion | `5044`, `5000`, `9600` |
| TheHive | Alert and case management | `http://localhost:9000` |
| Cortex | Observable enrichment | `http://localhost:9001` |
| MISP | Threat intelligence | `https://localhost:8443` |
| Shuffle | SOAR workflows | `http://localhost:3001` |
| MinIO | TheHive object storage | `http://localhost:9003` |
| Portainer | Docker management | `http://localhost:9004` |

## Repository Structure

```text
.
├── docker-compose.yml
├── Dockerfile.sync
├── Dockerfile.ai-soc-assistant
├── sync.py
├── create_elastic_alerts.py
├── mini_soc_alert_generator.py
├── logs.py
├── misp.py
├── ai-soc-assistant/
│   ├── app.py
│   ├── auto_worker.py
│   ├── config.py
│   ├── cortex_client.py
│   ├── llm_client.py
│   ├── observable_extractor.py
│   ├── playbook_selector.py
│   ├── report_writer.py
│   ├── thehive_client.py
│   ├── playbooks/
│   ├── prompts/
│   ├── rules/
│   ├── samples/
│   └── outputs/
├── scripts/
│   ├── create_direct_o365_signal_alert.py
│   ├── inject_o365_mass_sharing_events.py
│   ├── send_ssh_bruteforce_logs.py
│   └── upsert_o365_elastic_rule.py
├── elasticsearch/config/
├── kibana/config/
├── logstash/config/
├── logstash/pipeline/
├── thehive/config/
├── cortex/config/
├── cortex/analyzers/
└── misp/config/
```

Generated reports, presentation files, caches, local logs, and secrets are intentionally excluded from Git.

## Requirements

- Docker
- Docker Compose
- Python 3.11 or newer for helper scripts
- Enough RAM to run Elastic, TheHive, Cortex, MISP, and Shuffle together
- An LLM API key for AI analysis

## Configuration

Create or update the root `.env` file with local values. Do not commit real secrets.

Important variables:

```text
ELASTIC_VERSION
ELASTIC_PASSWORD
ELASTIC_MEMORY
THEHIVE_VERSION
THEHIVE_SECRET
THEHIVE_API_KEY
CORTEX_URL
CORTEX_API_KEY
LLM_PROVIDER
LLM_BASE_URL
LLM_MODEL
LLM_API_KEY
AUTO_POLL_INTERVAL
AUTO_ALERT_RANGE
AUTO_ANALYZER_NAMES
CASSANDRA_VERSION
MINIO_ROOT_USER
MINIO_ROOT_PASSWORD
REDIS_PASSWORD
SHUFFLE_VERSION
NETWORK_SUBNET
TZ
```

For standalone AI assistant usage, use:

```text
ai-soc-assistant/.env.example
```

as the template for your local environment values.

## Quick Start

Start the lab:

```bash
docker compose up -d --build
```

Check containers:

```bash
docker compose ps
```

Open the main interfaces:

- Kibana: `http://localhost:5601`
- TheHive: `http://localhost:9000`
- Cortex: `http://localhost:9001`
- Shuffle: `http://localhost:3001`
- MISP: `https://localhost:8443`
- Portainer: `http://localhost:9004`

Stop the lab:

```bash
docker compose down
```

Remove containers and volumes:

```bash
docker compose down -v
```

## AI SOC Assistant

Install local Python dependencies:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r ai-soc-assistant/requirements.txt
```

Analyze a sample alert:

```bash
cd ai-soc-assistant
python app.py --sample samples/sample_sql_injection_alert.json
```

Preview the LLM prompt without calling the model:

```bash
cd ai-soc-assistant
python app.py --sample samples/sample_sql_injection_alert.json --show-prompt
```

Analyze a TheHive alert:

```bash
cd ai-soc-assistant
python app.py --alert-id '~123456789'
```

Analyze a TheHive alert and write the result back:

```bash
cd ai-soc-assistant
python app.py --alert-id '~123456789' --write-back
```

Run one automation cycle:

```bash
cd ai-soc-assistant
python auto_worker.py --once
```

The Docker service `ai-soc-automation` runs the worker continuously.

## Useful Scripts

Create or update the tuned Office 365 mass sharing Elastic rule:

```bash
python scripts/upsert_o365_elastic_rule.py --profile tuned
```

Push the before-tuning version of the same rule:

```bash
python scripts/upsert_o365_elastic_rule.py --profile before-tuning
```

Send SSH brute force test logs:

```bash
python scripts/send_ssh_bruteforce_logs.py
```

Generate Mini SOC test events:

```bash
python mini_soc_alert_generator.py --help
```

Create a direct test alert in Elastic:

```bash
python create_elastic_alerts.py
```

## Logs

Sync worker:

```bash
docker logs -f elastic-thehive-sync
```

AI automation worker:

```bash
docker logs -f ai-soc-automation
```

Elasticsearch:

```bash
docker logs -f elasticsearch
```

TheHive:

```bash
docker logs -f thehive
```

## Outputs

AI-generated files are written to:

```text
ai-soc-assistant/outputs/
```

Common output files:

- `*_prompt.txt`
- `*_ai_report.md`
- `*_playbook_not_found.md`
- `automation_state.json`

Only `ai-soc-assistant/outputs/README.md` is kept in Git. Runtime output files are ignored.

## Security Notes

- This is a lab environment, not a hardened production deployment.
- Rotate all default passwords and API keys before using it outside a private machine.
- Keep `.env` private.
- Do not commit generated alert reports if they contain sensitive data.
- Several services mount the Docker socket. Treat those containers as privileged.
- Review hardcoded demo credentials before sharing or deploying the stack.

## Troubleshooting

Check the full stack:

```bash
docker compose ps
```

Check Elasticsearch health:

```bash
curl -u elastic:$ELASTIC_PASSWORD http://localhost:9200/_cluster/health
```

If TheHive is not ready, inspect dependencies:

```bash
docker compose ps cassandra minio thehive-redis elasticsearch thehive
```

If alerts are not synced to TheHive, inspect:

```bash
docker logs elastic-thehive-sync
```

If AI reports are not created, verify:

- `LLM_API_KEY` is configured.
- `THEHIVE_API_KEY` is valid.
- `CORTEX_API_KEY` is valid.
- TheHive alerts are still in `New` status.
- The alert ID is not already present in `ai-soc-assistant/outputs/automation_state.json`.

## Git Hygiene

The repository intentionally ignores:

- `.env`
- `rapport/`
- `prez/`
- Python caches
- local logs
- generated AI reports
- local CSV/XLSX exports
- temporary notes and build artifacts
