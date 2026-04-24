# AI-Powered Log Anomaly Detector MVP

This repository contains one hackathon-ready system with two runnable Python processes and one shared root `.env` file:

- main service: Telegram bot UI + analyzed alert API + SQLite storage
- parser service: raw log ingestion + normalization + AI forwarding + heartbeat

Telegram remains the only user-facing UI.

## Architecture

The pipeline is:

1. Victim server laptop sends raw log lines to the parser service.
2. Parser service receives `POST /ingest-log-line`.
3. Parser normalizes the raw log line into a structured event.
4. Parser forwards that normalized event to the AI laptop at `AI_ANALYZE_URL`.
5. AI returns `score`, `severity`, `category`, `explanation`, and `recommended_action`.
6. Parser converts that response into the existing analyzed-alert contract.
7. Parser posts the final analyzed alert to the main API `POST /ingest-alert`.
8. Main service stores the alert and sends the Telegram notification.

The parser also sends heartbeat updates to the main API at `POST /heartbeat/parser`.

## Repository Structure

```text
.
|-- app/
|   |-- __init__.py
|   |-- api.py
|   |-- bot.py
|   |-- config.py
|   |-- demo.py
|   |-- formatter.py
|   |-- main.py
|   |-- models.py
|   |-- services.py
|   |-- storage.py
|   `-- utils.py
|-- parser_service/
|   |-- __init__.py
|   |-- api.py
|   |-- config.py
|   |-- forwarder.py
|   |-- main.py
|   |-- models.py
|   |-- parsers.py
|   `-- service.py
|-- tests/
|   |-- test_config_integration.py
|   |-- test_formatter.py
|   |-- test_models.py
|   |-- test_parser_service.py
|   `-- test_storage.py
|-- .env.example
|-- requirements.txt
|-- run_bot.py
|-- run_parser.py
`-- README.md
```

## One Root `.env`

This project uses exactly one shared `.env` at the repository root.

- main service reads the root `.env`
- parser service reads the same root `.env`
- parser config is resolved from the repository root even if the parser is started from inside `parser_service/`

Use this root layout:

```dotenv
BOT_TOKEN=
ADMIN_CHAT_ID=

MAIN_API_HOST=0.0.0.0
MAIN_API_PORT=8000
MAIN_SQLITE_PATH=alerts.db
MAIN_DEMO_MODE_DEFAULT=false
MAIN_HEARTBEAT_STALE_SECONDS=60
MAIN_LOG_LEVEL=INFO

PARSER_HOST=0.0.0.0
PARSER_PORT=9001
PARSER_LOG_LEVEL=INFO
PARSER_HTTP_TIMEOUT_SECONDS=5
PARSER_HEARTBEAT_INTERVAL_SECONDS=12

AI_ANALYZE_URL=http://<AI_IP>:9000/analyze

NETWORK_SERVER_NAME=victim-laptop
```

Notes:

- `MAIN_API_HOST=0.0.0.0` makes the main service reachable from other laptops.
- `PARSER_HOST=0.0.0.0` makes the parser reachable from the victim server laptop.
- The parser derives its internal main API base URL from `MAIN_API_HOST` and `MAIN_API_PORT`.
- If `MAIN_API_HOST` is `0.0.0.0`, the parser safely uses loopback internally for same-laptop calls while the server still binds on all interfaces.

## Main Service

Responsibilities:

- Telegram bot commands:
  - `/start`
  - `/help`
  - `/status`
  - `/alerts`
  - `/summary`
  - `/anomaly <id>`
  - `/demo_on`
  - `/demo_off`
- analyzed alert ingestion
- SQLite persistence
- parser/detector heartbeat tracking
- demo mode

Endpoints:

- `POST /ingest-alert`
- `POST /heartbeat/parser`
- `POST /heartbeat/detector`
- `GET /health`
- `GET /recent-alerts`

## Parser Service

Responsibilities:

- receive raw logs over HTTP
- normalize log lines into structured events
- forward normalized events to the AI laptop
- convert AI output into the existing `AlertIn` payload
- send final analyzed alerts to the main API
- send parser heartbeat to the main API
- keep working even if raw logs are malformed or AI is temporarily down

Endpoints:

- `POST /ingest-log-line`
- `GET /health`
- `GET /recent-events`

Reliability behavior:

- malformed log lines are normalized best-effort
- AI forwarding failures do not crash the parser
- heartbeat failures do not crash the parser
- if AI is unavailable, parser falls back to a simple heuristic analysis so the demo remains usable

## Data Contracts

### Raw log line into parser

`POST /ingest-log-line`

```json
{
  "source": "nginx",
  "raw_line": "192.168.43.25 - - [24/Apr/2026:14:21:03 +0500] \"GET /admin/login HTTP/1.1\" 403 512",
  "source_ip": "192.168.43.25",
  "timestamp": "2026-04-24T14:21:03",
  "metadata": {
    "hostname": "victim-laptop"
  }
}
```

Optional fields:

- `id`
- `timestamp`
- `source`
- `source_ip`
- `metadata`

### Normalized event from parser to AI

```json
{
  "id": "evt_20260424142103_abc12345",
  "timestamp": "2026-04-24T14:21:03",
  "source": "nginx",
  "source_ip": "192.168.43.25",
  "event_type": "admin_access",
  "raw_line": "192.168.43.25 - - [24/Apr/2026:14:21:03 +0500] \"GET /admin/login HTTP/1.1\" 403 512",
  "normalized_fields": {
    "method": "GET",
    "path": "/admin/login",
    "status_code": 403,
    "response_bytes": 512,
    "suspicious_tokens": [
      "admin_path"
    ],
    "metadata": {
      "hostname": "victim-laptop"
    }
  },
  "metadata": {
    "hostname": "victim-laptop"
  }
}
```

### AI response expected by parser

```json
{
  "score": 0.91,
  "severity": "high",
  "category": "web",
  "explanation": "Repeated suspicious requests with SQL injection patterns and denied responses.",
  "recommended_action": "investigate"
}
```

### Final analyzed alert into main API

`POST /ingest-alert`

```json
{
  "id": "evt_00124",
  "timestamp": "2026-04-24T14:21:03",
  "source": "nginx",
  "source_ip": "192.168.43.25",
  "event_type": "http_request",
  "raw_line": "GET /admin/login HTTP/1.1 ...",
  "score": 0.91,
  "severity": "high",
  "category": "web",
  "explanation": "Repeated suspicious requests with SQL injection patterns and denied responses.",
  "recommended_action": "investigate"
}
```

This analyzed-alert contract is unchanged.

### Parser heartbeat payload

`POST /heartbeat/parser`

```json
{
  "service": "parser",
  "timestamp": "2026-04-24T14:21:03",
  "status": "online"
}
```

## Setup

1. Create and activate a Python 3.11+ virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Copy `.env.example` to `.env`.
4. Fill in:
   - Telegram bot token
   - Telegram admin chat ID
   - AI laptop IP in `AI_ANALYZE_URL`
   - any hostname label you want in `NETWORK_SERVER_NAME`

## Run Commands

Main bot/API:

```bash
python run_bot.py
```

Parser service:

```bash
python run_parser.py
```

Optional parser run from inside the parser folder:

```bash
cd parser_service
python main.py
```

That still resolves the same root `.env`.

## curl Examples

If you are using PowerShell on Windows, prefer `curl.exe`.

### POST `/ingest-log-line`

```bash
curl -X POST http://127.0.0.1:9001/ingest-log-line \
  -H "Content-Type: application/json" \
  -d '{
    "source": "nginx",
    "raw_line": "192.168.43.25 - - [24/Apr/2026:14:21:03 +0500] \"GET /admin/login HTTP/1.1\" 403 512",
    "metadata": {
      "hostname": "victim-laptop"
    }
  }'
```

### POST `/heartbeat/parser`

```bash
curl -X POST http://127.0.0.1:8000/heartbeat/parser \
  -H "Content-Type: application/json" \
  -d '{
    "service": "parser",
    "timestamp": "2026-04-24T14:21:03",
    "status": "online"
  }'
```

### POST `/ingest-alert`

```bash
curl -X POST http://127.0.0.1:8000/ingest-alert \
  -H "Content-Type: application/json" \
  -d '{
    "id": "evt_00124",
    "timestamp": "2026-04-24T14:21:03",
    "source": "nginx",
    "source_ip": "192.168.43.25",
    "event_type": "http_request",
    "raw_line": "GET /admin/login HTTP/1.1 ...",
    "score": 0.91,
    "severity": "high",
    "category": "web",
    "explanation": "Repeated suspicious requests with SQL injection patterns and denied responses.",
    "recommended_action": "investigate"
  }'
```

### PowerShell examples

```powershell
curl.exe -X POST http://127.0.0.1:9001/ingest-log-line `
  -H "Content-Type: application/json" `
  -d "{\"source\":\"nginx\",\"raw_line\":\"192.168.43.25 - - [24/Apr/2026:14:21:03 +0500] \\\"GET /admin/login HTTP/1.1\\\" 403 512\",\"metadata\":{\"hostname\":\"victim-laptop\"}}"
```

```powershell
curl.exe -X POST http://127.0.0.1:8000/heartbeat/parser `
  -H "Content-Type: application/json" `
  -d "{\"service\":\"parser\",\"timestamp\":\"2026-04-24T14:21:03\",\"status\":\"online\"}"
```

```powershell
curl.exe -X POST http://127.0.0.1:8000/ingest-alert `
  -H "Content-Type: application/json" `
  -d "{\"id\":\"evt_00124\",\"timestamp\":\"2026-04-24T14:21:03\",\"source\":\"nginx\",\"source_ip\":\"192.168.43.25\",\"event_type\":\"http_request\",\"raw_line\":\"GET /admin/login HTTP/1.1 ...\",\"score\":0.91,\"severity\":\"high\",\"category\":\"web\",\"explanation\":\"Repeated suspicious requests with SQL injection patterns and denied responses.\",\"recommended_action\":\"investigate\"}"
```

## Demo Flow

1. Start the main service with `python run_bot.py`.
2. Start the parser service with `python run_parser.py`.
3. Confirm the main API is up with `/status` in Telegram or `GET /health`.
4. Send a raw log line to the parser at `http://<YOUR_LAPTOP_IP>:9001/ingest-log-line`.
5. Let the parser forward the normalized event to the AI laptop.
6. The parser receives the AI response and posts the final analyzed alert to the main API.
7. Show the result in Telegram with `/alerts`, `/summary`, and `/anomaly <id>`.

## Tests

```bash
pytest
```

## Notes

- The parser remains a separate process and is not mixed into the Telegram bot code.
- The existing `/ingest-alert` contract is preserved.
- Duplicate alert IDs remain safe because the main storage layer already ignores duplicates.
- Both services now use one shared root `.env`.
