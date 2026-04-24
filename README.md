# AI-Powered Log Anomaly Detector MVP

This repository now contains two cleanly separated services for hackathon case #14:

- `app/`: the main Telegram bot UI and analyzed-alert API
- `parser_service/`: the raw log parser service that sits in front of the AI laptop

Telegram remains the only user-facing UI.

## Architecture

The intended pipeline is:

1. Victim server laptop sends raw log lines to the parser service on your laptop.
2. Parser service normalizes each raw log line into a structured event.
3. Parser service forwards the normalized event to the AI service on another laptop.
4. AI service returns `score`, `severity`, `category`, `explanation`, and `recommended_action`.
5. Parser service sends the final analyzed alert to the existing main API `/ingest-alert`.
6. Main bot/API stores the alert and sends the Telegram notification.

Network layout:

- Main bot/API binds to `API_HOST` and `API_PORT`, usually `0.0.0.0:8000`
- Parser service binds to `PARSER_HOST` and `PARSER_PORT`, usually `0.0.0.0:9001`
- Parser calls the AI laptop at `PARSER_AI_URL`
- Parser sends heartbeat to `PARSER_MAIN_API_URL/heartbeat/parser`

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
|   |-- .env.example
|   |-- api.py
|   |-- config.py
|   |-- forwarder.py
|   |-- main.py
|   |-- models.py
|   |-- parsers.py
|   `-- service.py
|-- tests/
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

## Main Service Features

The main bot/API service still owns:

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
- parser and detector heartbeat tracking
- demo mode for jury demos

Main API endpoints:

- `POST /ingest-alert`
- `POST /heartbeat/parser`
- `POST /heartbeat/detector`
- `GET /health`
- `GET /recent-alerts`

## Parser Service Features

The parser service is kept separate from the bot and exposes:

- `POST /ingest-log-line`
- `GET /health`
- `GET /recent-events`

Behavior of `POST /ingest-log-line`:

- accepts a raw log line payload over HTTP
- performs best-effort normalization even for malformed lines
- extracts fields like `source_ip`, `event_type`, HTTP path, method, and status code when available
- forwards the normalized event to the AI service
- sends the final analyzed alert to the existing main API `/ingest-alert`
- logs failures instead of crashing
- falls back to a simple parser-side heuristic analysis if the AI service is unavailable

The fallback analysis is intentionally simple and only exists to keep the demo stable if the AI laptop is unreachable.

## Data Contracts

### 1. Raw log line to parser

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

`id`, `timestamp`, `source`, and `source_ip` are optional. The parser will generate or infer them when possible.

### 2. Normalized event sent from parser to AI service

The parser forwards a normalized event shaped like:

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
    ]
  },
  "metadata": {
    "hostname": "victim-laptop"
  }
}
```

Recommended AI endpoint:

- `POST http://<AI_IP>:9000/analyze`

Expected AI response:

```json
{
  "score": 0.91,
  "severity": "high",
  "category": "web",
  "explanation": "Repeated suspicious requests with SQL injection patterns and denied responses.",
  "recommended_action": "investigate"
}
```

### 3. Final analyzed alert sent to main API

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

This contract is unchanged from the existing bot/API layer.

### 4. Heartbeat payload

`POST /heartbeat/parser` or `POST /heartbeat/detector`

```json
{
  "service": "parser",
  "timestamp": "2026-04-24T14:21:03",
  "status": "online"
}
```

The parser service sends this heartbeat automatically in the background to the main API.

## Setup

1. Create and activate a Python 3.11+ virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Copy `.env.example` to `.env`.
4. Fill in your Telegram bot token, admin chat ID, and laptop IPs.

## Environment Variables

Main bot/API:

- `BOT_TOKEN`
- `ADMIN_CHAT_ID`
- `API_HOST`
- `API_PORT`
- `SQLITE_PATH`
- `DEMO_MODE_DEFAULT`
- `HEARTBEAT_STALE_SECONDS`
- `LOG_LEVEL`

Parser service:

- `PARSER_HOST`
- `PARSER_PORT`
- `PARSER_MAIN_API_URL`
- `PARSER_AI_URL`
- `PARSER_HEARTBEAT_INTERVAL_SECONDS`
- `PARSER_REQUEST_TIMEOUT_SECONDS`
- `PARSER_FALLBACK_ANALYSIS_ENABLED`
- `PARSER_RECENT_EVENTS_LIMIT`

Recommended hotspot-friendly values:

- `API_HOST=0.0.0.0`
- `PARSER_HOST=0.0.0.0`

When another laptop needs to reach one of these services, use your laptop's hotspot IP in the request URL, not `127.0.0.1`.

## Run Commands

### 1. Main bot/API service

```bash
python run_bot.py
```

This starts:

- Telegram bot polling
- main FastAPI ingestion API on port `8000`
- demo-mode generator loop

### 2. Parser service

```bash
python run_parser.py
```

This starts:

- parser FastAPI service on port `9001`
- background parser heartbeat loop to the main API

## curl Examples

If you are using PowerShell on Windows, prefer `curl.exe` instead of `curl`.

### Parser raw-log ingestion

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

### Parser heartbeat sent to main API

```bash
curl -X POST http://127.0.0.1:8000/heartbeat/parser \
  -H "Content-Type: application/json" \
  -d '{
    "service": "parser",
    "timestamp": "2026-04-24T14:21:03",
    "status": "online"
  }'
```

### Final analyzed alert sent to main API

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
3. Send `/status` in Telegram and confirm the main API is up.
4. Send a raw log line to `http://<YOUR_LAPTOP_IP>:9001/ingest-log-line`.
5. If the AI laptop is reachable, it will score the event.
6. If the AI laptop is down, the parser falls back to a simple local heuristic so the demo does not stall.
7. Open Telegram and use `/alerts`, `/summary`, and `/anomaly <id>` to show the final result.

## Tests

```bash
pytest
```

## Notes

- The parser remains a separate service and is not merged into `bot.py` or the Telegram command layer.
- The existing `/ingest-alert` contract is preserved.
- Parser heartbeat and AI forwarding failures are handled without crashing the parser service.
- The parser performs best-effort normalization for malformed log lines and stores recent normalized events in memory.
