import os
import asyncio
from datetime import datetime
from pathlib import Path
import httpx
from dotenv import load_dotenv

load_dotenv()

LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "access.log")
PARSER_FORWARD_URL = os.getenv("PARSER_FORWARD_URL", "http://10.204.7.1:9001/ingest-log-line")
SERVER_NAME = os.getenv("SERVER_NAME", "victim-laptop")

POLL_INTERVAL = 1.0


async def forward_line(client: httpx.AsyncClient, raw_line: str):
    payload = {
        "source": "nginx",
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "raw_line": raw_line,
        "metadata": {
            "hostname": SERVER_NAME,
        }
    }
    try:
        response = await client.post(PARSER_FORWARD_URL, json=payload, timeout=10.0)
        print(f"[forwarder] Sent → {response.status_code}")
    except httpx.ConnectError:
        print(f"[forwarder] Parser offline — retrying later")
    except Exception as e:
        print(f"[forwarder] Error: {type(e).__name__}: {e}")


async def start_forwarder():
    log_path = Path(LOG_FILE_PATH)

    while not log_path.exists():
        print(f"[forwarder] Waiting for log file...")
        await asyncio.sleep(2)

    with open(log_path, "r", encoding="utf-8") as f:
        f.seek(0, 2)
        position = f.tell()

    print(f"[forwarder] Watching {log_path}")

    async with httpx.AsyncClient() as client:
        while True:
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    f.seek(position)
                    new_lines = f.readlines()
                    position = f.tell()

                for line in new_lines:
                    line = line.strip()
                    if line:
                        await forward_line(client, line)

            except Exception as e:
                print(f"[forwarder] Read error: {e}")

            await asyncio.sleep(POLL_INTERVAL)