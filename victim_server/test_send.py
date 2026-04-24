import requests
from datetime import datetime

PARSER_URL = "http://10.204.7.1:9001/ingest-log-line"

payload = {
    "source": "nginx",
    "timestamp": datetime.now().isoformat(timespec="seconds"),
    "raw_line": '10.204.7.248 - - [24/Apr/2026:14:21:03 +0500] "GET /admin HTTP/1.1" 403 512',
    "metadata": {
        "hostname": "victim-laptop"
    }
}

r = requests.post(PARSER_URL, json=payload, timeout=5)
print(r.status_code, r.text)