from app.config import load_config
from parser_service.config import load_parser_config


def test_main_config_reads_unified_root_env_keys(tmp_path, monkeypatch) -> None:
    sqlite_path = tmp_path / "alerts.db"
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "BOT_TOKEN=test-token",
                "ADMIN_CHAT_ID=123456789",
                "MAIN_API_HOST=0.0.0.0",
                "MAIN_API_PORT=8000",
                f"MAIN_SQLITE_PATH={sqlite_path}",
                "MAIN_DEMO_MODE_DEFAULT=true",
                "MAIN_HEARTBEAT_STALE_SECONDS=75",
                "SHARED_API_KEY=team-secret",
                "MAIN_LOG_LEVEL=DEBUG",
            ]
        ),
        encoding="utf-8",
    )

    for key in (
        "BOT_TOKEN",
        "ADMIN_CHAT_ID",
        "MAIN_API_HOST",
        "MAIN_API_PORT",
        "MAIN_SQLITE_PATH",
        "MAIN_DEMO_MODE_DEFAULT",
        "MAIN_HEARTBEAT_STALE_SECONDS",
        "SHARED_API_KEY",
        "MAIN_LOG_LEVEL",
        "API_HOST",
        "API_PORT",
        "SQLITE_PATH",
        "DEMO_MODE_DEFAULT",
        "HEARTBEAT_STALE_SECONDS",
        "LOG_LEVEL",
    ):
        monkeypatch.delenv(key, raising=False)

    config = load_config(str(env_file))

    assert config.bot_token == "test-token"
    assert config.admin_chat_id == 123456789
    assert config.api_host == "0.0.0.0"
    assert config.api_port == 8000
    assert config.sqlite_path == str(sqlite_path)
    assert config.demo_mode_default is True
    assert config.heartbeat_stale_seconds == 75
    assert config.shared_api_key == "team-secret"
    assert config.log_level == "DEBUG"


def test_parser_config_uses_root_env_and_derives_main_api_url(tmp_path, monkeypatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "MAIN_API_HOST=0.0.0.0",
                "MAIN_API_PORT=8000",
                "PARSER_HOST=0.0.0.0",
                "PARSER_PORT=9001",
                "PARSER_LOG_LEVEL=WARNING",
                "PARSER_HTTP_TIMEOUT_SECONDS=5",
                "PARSER_HEARTBEAT_INTERVAL_SECONDS=12",
                "AI_ANALYZE_URL=http://192.168.1.50:9000/analyze",
                "NETWORK_SERVER_NAME=victim-laptop",
                "SHARED_API_KEY=team-secret",
            ]
        ),
        encoding="utf-8",
    )

    for key in (
        "MAIN_API_HOST",
        "MAIN_API_PORT",
        "PARSER_HOST",
        "PARSER_PORT",
        "PARSER_LOG_LEVEL",
        "PARSER_HTTP_TIMEOUT_SECONDS",
        "PARSER_HEARTBEAT_INTERVAL_SECONDS",
        "AI_ANALYZE_URL",
        "NETWORK_SERVER_NAME",
        "SHARED_API_KEY",
        "API_HOST",
        "API_PORT",
        "LOG_LEVEL",
        "PARSER_AI_URL",
        "PARSER_REQUEST_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(key, raising=False)

    config = load_parser_config(str(env_file))

    assert config.parser_host == "0.0.0.0"
    assert config.parser_port == 9001
    assert config.main_api_url == "http://127.0.0.1:8000"
    assert config.ai_service_url == "http://192.168.1.50:9000/analyze"
    assert config.network_server_name == "victim-laptop"
    assert config.shared_api_key == "team-secret"
    assert config.request_timeout_seconds == 5.0
    assert config.heartbeat_interval_seconds == 12
    assert config.log_level == "WARNING"
