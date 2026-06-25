"""End-to-end TenantGuard write-method checks against the demo FastAPI app."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from app.data import reset_demo_data
from app.main import app

from tenantguard.config import load_config, load_env_file, resolve_tokens
from tenantguard.reporters.html_reporter import render_html_report
from tenantguard.reporters.json_reporter import render_json_report
from tenantguard.reporters.markdown_reporter import render_markdown_report
from tenantguard.results import CheckStatus
from tenantguard.runner import RunOptions, run_checks

DEMO_PORT = 18001
DEMO_BASE_URL = f"http://127.0.0.1:{DEMO_PORT}"
CONFIG_PATH = Path("examples/configs/tenantguard-demo-write.yml")
ENV_PATH = Path("examples/vulnerable-fastapi-app/.env.demo")


@pytest.fixture(scope="module")
def demo_server() -> str:
    config = uvicorn.Config(app, host="127.0.0.1", port=DEMO_PORT, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    for _ in range(50):
        try:
            response = httpx.get(f"{DEMO_BASE_URL}/health", timeout=0.2)
            if response.status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    else:
        pytest.fail("Demo server did not become ready in time.")

    yield DEMO_BASE_URL
    server.should_exit = True


@pytest.fixture(autouse=True)
def _reset_demo_data() -> None:
    reset_demo_data()


def test_tenantguard_write_demo_end_to_end(demo_server: str) -> None:
    config = load_config(CONFIG_PATH)
    config.target.base_url = demo_server
    env = load_env_file(ENV_PATH)
    runtime = resolve_tokens(config, env)

    result = run_checks(
        config,
        runtime,
        RunOptions(confirm_authorized_scope=False),
    )

    by_id = {check.id: check for check in result.checks}
    assert result.summary.total == 4
    assert result.summary.failed == 1
    assert result.summary.passed == 3
    assert result.summary.errors == 0
    assert result.summary.highest_failed_severity is not None
    assert result.summary.highest_failed_severity.value == "critical"
    assert by_id["TG-WRITE-001"].status == CheckStatus.FAILED
    assert by_id["TG-WRITE-002"].status == CheckStatus.PASSED
    assert by_id["TG-WRITE-003"].status == CheckStatus.PASSED
    assert by_id["TG-WRITE-004"].status == CheckStatus.PASSED

    json_output = render_json_report(result)
    markdown_output = render_markdown_report(result)
    html_output = render_html_report(result)
    assert "demo-token" not in json_output
    assert "demo-token" not in markdown_output
    assert "demo-token" not in html_output
    assert '"amount": 9999' in html_output or "9999" in html_output
    assert "<script>" not in html_output
    json.loads(json_output)


def test_tenantguard_write_demo_secure_only_excludes_vulnerable(demo_server: str) -> None:
    config = load_config(CONFIG_PATH)
    config.target.base_url = demo_server
    env = load_env_file(ENV_PATH)
    runtime = resolve_tokens(config, env)

    result = run_checks(
        config,
        runtime,
        RunOptions(confirm_authorized_scope=False, exclude=["vulnerable"]),
    )

    assert result.summary.total == 3
    assert result.summary.failed == 0
    assert result.summary.passed == 3
    assert result.summary.errors == 0
