# AI-Powered Log Anomaly Detector Telegram Bot

This project is the Telegram bot and alert UI layer for hackathon case #14, "AI-Powered Log Anomaly Detector".

It gives your team a working demo surface immediately:

- Telegram is the main UI
- FastAPI exposes a local ingestion API for teammate integrations
- SQLite stores recent alerts, heartbeats, and demo-mode settings
- Demo mode generates realistic fake anomalies every few seconds

## Architecture

There are two runtime layers in one Python app:

1. Telegram Bot UI
- `/start` for intro
- `/help` for commands and demo workflow
- `/status` for bot/API/service health plus alert counters
- `/alerts` for the last 5 alerts
- `/summary` for severity, category, and top IP statistics
- `/anomaly <id>` for the full expanded anomaly view
- `/demo_on` and `/demo_off` to toggle autonomous demo alerts

2. Local Ingestion API
- `POST /ingest-alert`
- `POST /heartbeat/parser`
- `POST /heartbeat/detector`
- `GET /health`
- `GET /recent-alerts`

## Teammate Integration Contract

### Incoming analyzed anomaly alert

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

Behavior:

- payload is validated with Pydantic
- duplicates do not crash the app
- valid alerts are persisted to SQLite
- a formatted Telegram notification is sent to the configured admin chat
- if Telegram send fails, the API still keeps running

### Heartbeat payload

`POST /heartbeat/parser` or `POST /heartbeat/detector`

```json
{
  "service": "parser",
  "timestamp": "2026-04-24T14:21:03",
  "status": "online"
}
```

`service` must match the endpoint path. Heartbeats are marked stale when older than `HEARTBEAT_STALE_SECONDS`.

## Project Structure

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
|-- tests/
|   |-- test_formatter.py
|   |-- test_models.py
|   `-- test_storage.py
|-- .env.example
|-- requirements.txt
|-- run_bot.py
`-- README.md
```

## Setup

1. Create and activate a Python 3.11+ virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Copy `.env.example` to `.env` and fill in your Telegram values.

## Environment Variables

Required:

- `BOT_TOKEN`
- `ADMIN_CHAT_ID`

Configurable:

- `API_HOST`
- `API_PORT`
- `SQLITE_PATH`
- `DEMO_MODE_DEFAULT`
- `HEARTBEAT_STALE_SECONDS`
- `LOG_LEVEL`

## Run Bot + API

```bash
python run_bot.py
```

This starts:

- Telegram bot polling
- FastAPI ingestion server
- background demo generator loop

## Test With curl

If you are using PowerShell on Windows, prefer `curl.exe` instead of `curl` so you call the real curl binary rather than the built-in alias.

### Health check

```bash
curl http://127.0.0.1:8000/health
```

### Ingest an alert

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

### Parser heartbeat

```bash
curl -X POST http://127.0.0.1:8000/heartbeat/parser \
  -H "Content-Type: application/json" \
  -d '{
    "service": "parser",
    "timestamp": "2026-04-24T14:21:03",
    "status": "online"
  }'
```

### Detector heartbeat

```bash
curl -X POST http://127.0.0.1:8000/heartbeat/detector \
  -H "Content-Type: application/json" \
  -d '{
    "service": "detector",
    "timestamp": "2026-04-24T14:21:03",
    "status": "online"
  }'
```

### Recent alerts

```bash
curl "http://127.0.0.1:8000/recent-alerts?limit=5"
```

### PowerShell-friendly examples

```powershell
curl.exe -X POST http://127.0.0.1:8000/ingest-alert `
  -H "Content-Type: application/json" `
  -d "{\"id\":\"evt_00124\",\"timestamp\":\"2026-04-24T14:21:03\",\"source\":\"nginx\",\"source_ip\":\"192.168.43.25\",\"event_type\":\"http_request\",\"raw_line\":\"GET /admin/login HTTP/1.1 ...\",\"score\":0.91,\"severity\":\"high\",\"category\":\"web\",\"explanation\":\"Repeated suspicious requests with SQL injection patterns and denied responses.\",\"recommended_action\":\"investigate\"}"
```

```powershell
curl.exe -X POST http://127.0.0.1:8000/heartbeat/parser `
  -H "Content-Type: application/json" `
  -d "{\"service\":\"parser\",\"timestamp\":\"2026-04-24T14:21:03\",\"status\":\"online\"}"
```

```powershell
curl.exe -X POST http://127.0.0.1:8000/heartbeat/detector `
  -H "Content-Type: application/json" `
  -d "{\"service\":\"detector\",\"timestamp\":\"2026-04-24T14:21:03\",\"status\":\"online\"}"
```

## Telegram Demo Workflow

1. Start the app with `python run_bot.py`.
2. Open the bot from the admin chat configured in `.env`.
3. Send `/start`.
4. Send `/demo_on`.
5. Wait a few seconds for alerts to arrive.
6. Use `/alerts`, `/summary`, and `/anomaly <id>`.
7. Send `/demo_off` when you want to freeze the demo state.

## 5-Minute Jury Demo Script

1. Open Telegram and show `/start`.
2. Show `/status` before any teammate traffic arrives.
3. Send `/demo_on` and let a couple of realistic alerts appear automatically.
4. Use `/alerts` to show the compact feed.
5. Use `/summary` to show quick analytics.
6. Open one detailed alert with `/anomaly <id>`.
7. Hit `/ingest-alert` with `curl` to prove teammate services can push live data into the same UI.
8. Hit `/heartbeat/parser` and `/heartbeat/detector`, then show `/status` again.

## Running Tests

```bash
pytest
```

## Notes

- This project intentionally does not implement parsing, ML detection, or blocking actions.
- It is focused only on Telegram UI, alert persistence, summary views, heartbeat tracking, and teammate integration contracts.
