"""End-to-end TenantGuard checks against the demo FastAPI app."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from app.main import app

from tenantguard.config import load_config, load_env_file, resolve_tokens
from tenantguard.reporters.json_reporter import render_json_report
from tenantguard.results import CheckStatus
from tenantguard.runner import RunOptions, run_checks

DEMO_PORT = 18000
DEMO_BASE_URL = f"http://127.0.0.1:{DEMO_PORT}"
CONFIG_PATH = Path("examples/configs/tenantguard-demo.yml")
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


def test_tenantguard_demo_end_to_end(demo_server: str) -> None:
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
    assert result.summary.total >= 8
    assert by_id["TG-DEMO-001"].status == CheckStatus.FAILED
    assert by_id["TG-DEMO-002"].status == CheckStatus.FAILED
    assert by_id["TG-DEMO-003"].status == CheckStatus.FAILED
    assert by_id["TG-DEMO-004"].status == CheckStatus.PASSED
    assert by_id["TG-DEMO-005"].status == CheckStatus.PASSED
    assert by_id["TG-DEMO-006"].status == CheckStatus.PASSED
    assert by_id["TG-DEMO-007"].status == CheckStatus.PASSED
    assert by_id["TG-DEMO-008"].status == CheckStatus.PASSED

    rendered = render_json_report(result)
    assert "demo-token" not in rendered
    assert "TENANT_B_INVOICE_MARKER" in rendered or "TG-DEMO-001" in rendered
    json.loads(rendered)
