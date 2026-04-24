# AI-Powered Log Anomaly Detector

Real-time log anomaly detection system with Telegram alerting, local AI analysis, and a demo victim server.

Built by **matrixpwd** for **AITU Hackathon 2026**, Case #14. The project analyzes server logs in near real time, detects suspicious activity, explains it with a local LLM, and sends alerts to Telegram. :contentReference[oaicite:2]{index=2} :contentReference[oaicite:3]{index=3}

## Overview

This repository is a **monorepo** and now contains the full system:

- `app/` — central node main service: Telegram bot UI, analyzed-alert API, SQLite storage
- `parser_service/` — raw log ingestion, normalization, AI forwarding, fallback analysis
- `ai_service/` — AI adapter service for LM Studio / OpenAI-compatible inference
- `victim_server/` — demo server that generates access logs and forwards them to the parser
- `tests/` — tests for the central node and parser
- `docs/` — additional architecture, AI setup, and demo notes

Telegram is the main user-facing interface.

## Problem

Production servers generate thousands of log lines, and manual review is too slow. Most systems do not alert in real time, so attacks like brute-force, SQL injection, XSS, admin probing, and sensitive path scanning can stay hidden in normal traffic. This project solves that problem by analyzing each incoming log event automatically and immediately. :contentReference[oaicite:4]{index=4} :contentReference[oaicite:5]{index=5}

## How it works

The pipeline is:

1. A demo victim server receives traffic and writes access logs
2. The log forwarder sends new raw log lines to the parser
3. The parser normalizes each line into a structured event
4. The parser sends the normalized event to the AI adapter
5. The AI adapter calls LM Studio / OpenAI-compatible inference
6. The AI adapter returns:
   - `score`
   - `severity`
   - `category`
   - `explanation`
   - `recommended_action`
7. The parser converts that into the final alert contract
8. The main service stores the alert and sends a Telegram notification

If the AI service is unavailable, the parser automatically falls back to heuristic analysis so the system still works during demo conditions. :contentReference[oaicite:6]{index=6}

## Architecture

### Central node
Runs on the main laptop.

Responsibilities:
- Telegram bot
- analyzed-alert API
- SQLite storage
- parser service
- parser and detector heartbeat tracking

Processes:
- `python run_bot.py`
- `python run_parser.py`

Default ports:
- Main API: `8000`
- Parser service: `9001`

### AI node
Runs on the AI teammate laptop.

Responsibilities:
- expose `GET /health`
- expose `POST /analyze`
- accept normalized events from the parser
- call LM Studio / local OpenAI-compatible endpoint
- return structured JSON

Default port:
- AI adapter: `9000`

### Victim server node
Runs on the victim server laptop.

Responsibilities:
- expose demo routes such as `/`, `/login`, `/admin`, `/search`, `/health`
- write access logs in combined-style format
- forward new log lines to the parser

Default port:
- Demo server: `8080`

### Attacker / traffic generator
Runs on another laptop or client machine.

Responsibilities:
- generate test traffic
- simulate brute-force, admin probing, suspicious query strings, path scanning, and other attacks

The original demo architecture uses **4 laptops in one isolated hotspot**:
- victim server
- parser + bot
- AI analysis
- attacker :contentReference[oaicite:7]{index=7} :contentReference[oaicite:8]{index=8}

## Repository structure

```text
.
|-- app/                  # Main service: Telegram bot + analyzed alert API + storage
|-- parser_service/       # Parser service: raw log ingestion + normalization + AI forwarding
|-- ai_service/           # AI adapter for LM Studio / OpenAI-compatible endpoint
|-- victim_server/        # Demo victim server + log forwarder
|-- tests/
|-- docs/
|-- .env.example
|-- requirements.txt
|-- run_bot.py
|-- run_parser.py
`-- README.md
````

## Detected threats

The system is designed to detect demo threats such as:

* brute-force attempts on `/login`
* admin probing on `/admin`
* SQL injection-style query strings
* XSS-style input in query parameters
* path scanning for `/.env`, `/wp-login.php`, `/phpmyadmin`
* burst traffic / repeated request spikes 

## One root `.env`

The central node uses one shared root `.env`.

Copy `.env.example` to `.env` and fill in:

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
SHARED_API_KEY=
```

Notes:

* `MAIN_API_HOST=0.0.0.0` makes the main service reachable from other laptops
* `PARSER_HOST=0.0.0.0` makes the parser reachable from the victim server laptop
* leave `SHARED_API_KEY` empty for the simplest hackathon flow
* if `SHARED_API_KEY` is set, send `X-API-Key: <value>` to parser and main write endpoints

## Central node setup

Clone the repo:

```bash
git clone https://github.com/zalewko-droid/aitu-hachaton.git
cd aitu-hachaton
```

Install central node dependencies:

```bash
pip install -r requirements.txt
```

Create `.env`:

```bash
cp .env.example .env
```

Start the main service:

```bash
python run_bot.py
```

Start the parser service:

```bash
python run_parser.py
```

## AI node setup

Install AI adapter dependencies:

```bash
pip install -r ai_service/requirements.txt
```

Run the adapter:

```bash
python ai_service/adapter.py
```

Expected endpoints:

* `GET /health`
* `POST /analyze`

The adapter talks to LM Studio / OpenAI-compatible inference internally and returns strict JSON for the parser.

## Victim server setup

Install victim server dependencies:

```bash
pip install -r victim_server/requirements.txt
```

Run the server:

```bash
python victim_server/server.py
```

Useful environment variables for `victim_server`:

* `SERVER_HOST` default: `0.0.0.0`
* `SERVER_PORT` default: `8080`
* `SERVER_NAME` default: `victim-laptop`
* `LOG_FILE_PATH` default: `access.log`
* `PARSER_FORWARD_URL` default: parser endpoint

Before demo day, set `PARSER_FORWARD_URL` to the real parser endpoint of the central node.

## Health checks

Main API:

```bash
curl http://127.0.0.1:8000/health
```

Parser service:

```bash
curl http://127.0.0.1:9001/health
```

AI adapter:

```bash
curl http://127.0.0.1:9000/health
```

## Example requests

### Send a raw log line to the parser

```bash
curl -X POST http://127.0.0.1:9001/ingest-log-line \
  -H "Content-Type: application/json" \
  -d '{
    "source": "nginx",
    "raw_line": "10.204.7.225 - - [24/Apr/2026:14:26:15 +0500] \"GET /admin HTTP/1.1\" 403 512",
    "metadata": {
      "hostname": "victim-laptop"
    }
  }'
```

### Send parser heartbeat

```bash
curl -X POST http://127.0.0.1:8000/heartbeat/parser \
  -H "Content-Type: application/json" \
  -d '{
    "service": "parser",
    "timestamp": "2026-04-24T14:21:03",
    "status": "online"
  }'
```

### Send detector heartbeat

```bash
curl -X POST http://127.0.0.1:8000/heartbeat/detector \
  -H "Content-Type: application/json" \
  -d '{
    "service": "detector",
    "timestamp": "2026-04-24T14:21:03",
    "status": "online"
  }'
```

## Demo flow

1. Start `run_bot.py`
2. Start `run_parser.py`
3. Start `ai_service/adapter.py`
4. Start `victim_server/server.py`
5. Confirm `/health` on `8000`, `9001`, and `9000`
6. Confirm Telegram `/status`
7. Trigger one `/admin` request
8. Confirm Telegram alert
9. Trigger one auth or suspicious query scenario
10. Show `/alerts`, `/summary`, or `/anomaly <id>`

In the demo script, the team presents:

* the problem
* the 4-laptop architecture
* the AI analysis layer
* detected threats
* live Telegram alerting
* final results and next steps  

## Tests

Run from repository root:

```bash
python -m pytest
```

## Current limitations

* parser recent events are kept in memory
* the AI contract depends on stable structured JSON output
* the victim server uses a simple forwarder, not a production log pipeline
* this project is optimized for a hackathon demo, not production deployment

## Team

* **Maksatuly Tanat** — victim server
* **Zalesh Sultan** — parser + bot
* **Mikhailov Andrey** — AI analysis
* **Moldash Aidyn** — attacker  
Если хочешь, я следующим сообщением дам ещё готовые `docs/ARCHITECTURE.md` и `docs/AI_ENGINE_SETUP.md`.
```
