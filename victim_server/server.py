import os
import time
import asyncio
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

from logging_utils import write_access_log
from forwarder import start_forwarder

load_dotenv()

SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8080"))
SERVER_NAME = os.getenv("SERVER_NAME", "victim-laptop")

app = FastAPI()

DEMO_CREDENTIALS = {"username": "admin", "password": "admin123"}


@app.middleware("http")
async def access_log_middleware(request: Request, call_next):
    start = time.time()
    response = await call_next(request)

    client_ip = request.client.host if request.client else "127.0.0.1"
    timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0500")
    method = request.method
    path = request.url.path
    query = f"?{request.url.query}" if request.url.query else ""
    status = response.status_code
    user_agent = request.headers.get("user-agent", "-")
    referrer = request.headers.get("referer", "-")
    bytes_sent = int(response.headers.get("content-length", 0))

    log_line = (
        f'{client_ip} - - [{timestamp}] '
        f'"{method} {path}{query} HTTP/1.1" '
        f'{status} {bytes_sent} "{referrer}" "{user_agent}"'
    )

    write_access_log(log_line)
    return response


@app.get("/")
async def index():
    return {"status": "ok", "message": "Welcome"}


@app.post("/login")
async def login(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON"})
    if body.get("username") == DEMO_CREDENTIALS["username"] and body.get("password") == DEMO_CREDENTIALS["password"]:
        return JSONResponse(status_code=200, content={"message": "Login successful"})
    return JSONResponse(status_code=401, content={"error": "Unauthorized"})


@app.get("/admin")
async def admin():
    return JSONResponse(status_code=403, content={"error": "Forbidden"})


@app.get("/search")
async def search(q: str = ""):
    suspicious = ["'", '"', "<", ">", "script", "union", "select", "--", ";", "../"]
    if any(s in q.lower() for s in suspicious):
        return JSONResponse(status_code=403, content={"error": "Forbidden query"})
    return JSONResponse(status_code=200, content={"results": [], "query": q})


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(full_path: str):
    return JSONResponse(status_code=404, content={"error": "Not found"})


@app.on_event("startup")
async def on_startup():
    asyncio.create_task(start_forwarder())


if __name__ == "__main__":
    uvicorn.run("server:app", host=SERVER_HOST, port=SERVER_PORT, reload=False)