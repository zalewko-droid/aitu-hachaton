import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "access.log")


def write_access_log(line: str):
    try:
        Path(LOG_FILE_PATH).parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"[logging_utils] Failed to write log: {e}")
        