"""CI action references remain immutable and consistent across workflows."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import socket
import struct
import subprocess
import textwrap
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

WORKFLOW_DIRECTORY = Path(__file__).resolve().parents[2] / ".github/workflows"
WORKFLOWS = sorted(WORKFLOW_DIRECTORY.glob("*.yml"))


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.stem)
def test_actions_use_immutable_versioned_references(workflow: Path) -> None:
    actions = re.findall(r"^\s+(?:- )?uses: (\S+)(.*)$", workflow.read_text(), re.M)
    assert actions
    for action, comment in actions:
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", action), action
        assert re.fullmatch(r" # v\d+\.\d+\.\d+", comment), action


def test_action_versions_are_consistent_across_workflows() -> None:
    references: dict[str, str] = {}
    for workflow in WORKFLOWS:
        for action, reference in re.findall(
            r"^\s+(?:- )?uses: ([\w./-]+)@(\S+)", workflow.read_text(), re.M
        ):
            assert references.setdefault(action, reference) == reference, action


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.stem)
def test_jobs_pin_the_ubuntu_image(workflow: Path) -> None:
    runners = re.findall(r"^\s+runs-on: (\S+)$", workflow.read_text(), re.M)
    assert runners
    assert set(runners) == {"ubuntu-26.04"}


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.stem)
def test_uv_caches_are_isolated_by_workflow_and_job(workflow: Path) -> None:
    for inputs in re.findall(
        r"^      - uses: astral-sh/setup-uv@.*\n((?:^        .*\n)+)",
        workflow.read_text(),
        re.M,
    ):
        assert "cache-suffix: ${{ github.workflow }}-${{ github.job }}" in inputs


def test_core_native_checks_use_the_provider_venv_without_parent_segments() -> None:
    workflow = next(path for path in WORKFLOWS if path.stem == "component-checks").read_text()
    assert '"$GITHUB_WORKSPACE/rill-provider/tmp/ci-venv/bin/python" -m pytest' in workflow
    assert "../rill-provider/tmp/ci-venv/bin/python" not in workflow


def _anvil_probe_args() -> list[str]:
    lines = (WORKFLOW_DIRECTORY / "component-checks.yml").read_text().splitlines()
    marker = '"$RILLSWAP_ANVIL_RPC"'
    assert sum(line.strip() == marker for line in lines) == 1
    end = next(index for index, line in enumerate(lines) if line.strip() == marker)
    start = end
    while lines[start - 1].rstrip().endswith("\\"):
        start -= 1
    args = shlex.split("\n".join(lines[start : end + 1]).replace("\\\n", " "))
    assert args[0] == "curl"
    return args


def test_anvil_readiness_retries_are_bounded_and_read_only() -> None:
    args = _anvil_probe_args()
    assert "--retry-all-errors" in args
    assert "--retry-connrefused" in args
    assert "--fail" in args
    for flag, value in {
        "--retry": "20",
        "--retry-delay": "1",
        "--retry-max-time": "30",
        "--connect-timeout": "2",
        "--max-time": "3",
    }.items():
        assert args[args.index(flag) + 1] == value
    assert json.loads(args[args.index("--data") + 1]) == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_chainId",
        "params": [],
    }


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl required for readiness regression")
@pytest.mark.parametrize("recover", [True, False], ids=["transient-reset", "persistent-reset"])
def test_anvil_readiness_handles_resets_without_hiding_failure(recover: bool) -> None:
    attempts = 0

    class ResetHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - standard HTTP handler method
            nonlocal attempts
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            attempts += 1
            if not recover or attempts == 1:
                self.close_connection = True
                self.connection.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                )
                self.connection.close()
                return
            body = b'{"jsonrpc":"2.0","id":1,"result":"0x7a69"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), ResetHandler) as server:
        worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        worker.start()
        try:
            args = _anvil_probe_args()
            args[0] = str(shutil.which("curl"))
            # Shorten only the retry count; exercise the actual workflow's error handling.
            args[args.index("--retry") + 1] = "1"
            args[-1] = f"http://127.0.0.1:{server.server_port}"
            result = subprocess.run(  # noqa: S603 - checked-in probe, owned loopback server
                args, capture_output=True, text=True, check=False, timeout=10
            )
            assert attempts == 2
            assert (result.returncode == 0) == recover
            if recover:
                assert json.loads(result.stdout)["result"] == "0x7a69"
        finally:
            server.shutdown()
            worker.join(timeout=5)
            assert not worker.is_alive()


def _auto_retry_script() -> str:
    workflow = (WORKFLOW_DIRECTORY / "auto-retry.yml").read_text()
    marker = "          script: |\n"
    assert workflow.count(marker) == 1
    return textwrap.dedent(workflow.split(marker, 1)[1])


def test_auto_retry_has_a_narrow_privilege_and_workflow_boundary() -> None:
    workflow = (WORKFLOW_DIRECTORY / "auto-retry.yml").read_text()
    trigger = re.search(r"^on:\n(.*?)^permissions:", workflow, re.M | re.S)
    assert trigger is not None
    assert re.findall(r"^  (\w+):", trigger[1], re.M) == ["workflow_run"]
    assert re.findall(r"^    (\w+):", trigger[1], re.M) == ["workflows", "types"]
    assert re.findall(r"^      - (.+)$", trigger[1], re.M) == [
        "Component source checks",
        "completed",
    ]
    assert re.findall(r"^permissions: (.+)$", workflow, re.M) == ["{}"]
    permissions = re.findall(r"^    permissions:\n((?:      .*\n)+)", workflow, re.M)
    assert permissions == ["      actions: write\n"]
    assert re.findall(r"uses: ([\w/-]+)@", workflow) == ["actions/github-script"]
    assert not re.search(r"^\s+run:", workflow, re.M)
    assert "group: auto-retry-component-${{ github.event.workflow_run.id }}" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "github.event.workflow_run.conclusion == 'failure' &&" in workflow
    assert "github.event.workflow_run.run_attempt == 1" in workflow
    assert "          retries: 0\n" in workflow
    assert "${{" not in _auto_retry_script()


def _execute_auto_retry(
    source: dict[str, object] | None,
    current: dict[str, object],
    *,
    read_error: bool = False,
    rerun_error: bool = False,
) -> dict[str, object]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node required to execute the GitHub script regression")
    payload = {} if source is None else {"workflow_run": source}
    program = f"""
const calls = [];
const context = {{repo: {{owner: 'trusted-owner', repo: 'trusted-repo'}},
                  payload: {json.dumps(payload)}}};
const github = {{rest: {{actions: {{
  getWorkflowRun: async scope => {{
    calls.push({{api: 'get', ...scope}});
    if ({json.dumps(read_error)}) throw new Error('read unavailable');
    return {{data: {json.dumps(current)}}};
  }},
  reRunWorkflowFailedJobs: async scope => {{
    calls.push({{api: 'rerun', ...scope}});
    if ({json.dumps(rerun_error)}) throw new Error('rerun unavailable');
  }}
}}}}}};
const core = {{info: () => {{}}}};
try {{
  await (async () => {{
{_auto_retry_script()}
  }})();
  process.stdout.write(JSON.stringify({{calls, failed: false}}));
}} catch {{
  process.stdout.write(JSON.stringify({{calls, failed: true}}));
  process.exitCode = 1;
}}
"""
    result = subprocess.run(  # noqa: S603 - execute the inline workflow against API stubs
        [node, "--input-type=module", "--eval", program],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    assert result.returncode in (0, 1), result.stderr
    report: dict[str, object] = json.loads(result.stdout)
    assert report["failed"] == (result.returncode != 0)
    return report


def _failed_run() -> dict[str, object]:
    return {"id": 37, "status": "completed", "conclusion": "failure", "run_attempt": 1}


def test_auto_retry_reruns_once_using_only_the_base_repository_context() -> None:
    source = _failed_run() | {
        "head_repository": {"full_name": "untrusted/fork"},
        "repository": {"owner": "untrusted", "name": "other"},
        "head_branch": "untrusted input must never become executable code",
    }
    report = _execute_auto_retry(source, _failed_run())
    scope = {"owner": "trusted-owner", "repo": "trusted-repo", "run_id": 37}
    assert report == {
        "failed": False,
        "calls": [{"api": "get", **scope}, {"api": "rerun", **scope}],
    }


@pytest.mark.parametrize(
    "update",
    [
        {"conclusion": "success"},
        {"conclusion": "cancelled"},
        {"conclusion": "timed_out"},
        {"conclusion": None},
        {"run_attempt": 2},
        {"run_attempt": 3},
        {"id": 0},
        {"id": -1},
        {"id": "37"},
        {"id": 37.5},
        {"id": 2**53},
    ],
)
def test_auto_retry_ignores_ineligible_events(update: dict[str, object]) -> None:
    assert _execute_auto_retry(_failed_run() | update, _failed_run()) == {
        "failed": False,
        "calls": [],
    }


def test_auto_retry_ignores_missing_event_metadata() -> None:
    assert _execute_auto_retry(None, _failed_run()) == {"failed": False, "calls": []}


@pytest.mark.parametrize(
    "update",
    [
        {"run_attempt": 2},
        {"status": "in_progress"},
        {"status": "queued"},
        {"conclusion": "success"},
        {"id": 38},
    ],
)
def test_auto_retry_rechecks_live_state_before_rerunning(update: dict[str, object]) -> None:
    report = _execute_auto_retry(_failed_run(), _failed_run() | update)
    assert report == {
        "failed": False,
        "calls": [{"api": "get", "owner": "trusted-owner", "repo": "trusted-repo", "run_id": 37}],
    }


@pytest.mark.parametrize("operation", ["read", "rerun"])
def test_auto_retry_api_failures_remain_failures_without_repeated_posts(operation: str) -> None:
    report = _execute_auto_retry(
        _failed_run(),
        _failed_run(),
        read_error=operation == "read",
        rerun_error=operation == "rerun",
    )
    scope = {"owner": "trusted-owner", "repo": "trusted-repo", "run_id": 37}
    expected = [{"api": "get", **scope}]
    if operation == "rerun":
        expected.append({"api": "rerun", **scope})
    assert report == {"failed": True, "calls": expected}
