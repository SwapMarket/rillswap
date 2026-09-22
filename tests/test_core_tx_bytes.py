from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from contextlib import contextmanager, suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from rill_core.errors import ValidationError
from rill_core.settlement import FundingBindingTransactionMatch
from rill_core.wire.messages import ContractTerms, FundingBinding

from rill_provider import core_tx_bytes
from rill_provider.core_tx_bytes import (
    CoreAuthError,
    CoreProtocolError,
    CoreUnavailableError,
    RegtestCoreTransactionReader,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from rill_core.wire.types import NetworkIdentity

FIXTURES = Path(__file__).parent / "fixtures"
GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"


def _context() -> tuple[ContractTerms, FundingBinding, NetworkIdentity]:
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    document = (FIXTURES / manifest["fixture_path"]).read_bytes()
    assert hashlib.sha256(document).hexdigest() == manifest["sha256"]
    fixture = json.loads(document)
    terms = ContractTerms.model_validate_json(json.dumps(fixture["contract_terms"]))
    binding = FundingBinding.model_validate(
        {
            "contract_hash": fixture["contract_hash"],
            "funding_attempt_id": "ab" * 32,
            "binding_revision": 0,
            "funder_role": "client",
            "lineage_anchor_txid": "11" * 32,
            "lineage_anchor_vout": 0,
            "funding_txid": "22" * 32,
            "contract_vout": 1,
            "contract_value_sat": terms.economics.contract_amount_sat,
            "contract_script_pubkey": fixture["taproot_contract"]["script_pubkey"],
            "replaces_txid": None,
            "created_at": 1_700_000_000,
        }
    )
    return terms, binding, terms.network_identity


@contextmanager
def _server(
    respond: Callable[[dict[str, Any]], tuple[int, bytes]],
    requests: list[dict[str, Any]],
    *,
    header_mode: str = "normal",
) -> Iterator[int]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            content = self.rfile.read(int(self.headers["content-length"]))
            payload: dict[str, Any] = json.loads(content)
            requests.append(
                {
                    "path": self.path,
                    "auth": self.headers.get("authorization"),
                    "encoding": self.headers.get("accept-encoding"),
                    **payload,
                }
            )
            status, body = respond(payload)
            if header_mode == "normal":
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
            else:
                parts = (
                    f"HTTP/1.1 {status} OK\r\n".encode(),
                    *((b"X-Test-Pacing: 1\r\n",) * 18 if header_mode == "trickle" else ()),
                    b"Content-Type: application/json\r\n",
                    f"Content-Length: {len(body)}\r\n".encode(),
                    b"\r\n",
                )
                try:
                    for part in parts:
                        self.wfile.write(part)
                        self.wfile.flush()
                        if part != parts[-1]:
                            time.sleep(1.5 if header_mode == "stall" else 0.08)
                except (BrokenPipeError, ConnectionResetError):
                    return
            with suppress(BrokenPipeError):
                self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _cookie(tmp_path: Path, text: str = "__cookie__:secret") -> Path:
    path = tmp_path / "core.cookie"
    path.write_text(text)
    path.chmod(0o600)
    return path


def _success(payload: dict[str, Any]) -> tuple[int, bytes]:
    method = payload["method"]
    result: object = {
        "getblockchaininfo": {"chain": "regtest"},
        "getblockhash": GENESIS,
        "getrawtransaction": "02000000000100",
    }[method]
    return 200, json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}).encode()


def test_fetch_is_explicit_read_only_network_checked_and_cookie_rotates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    terms, binding, network = _context()
    requests: list[dict[str, Any]] = []
    received: list[bytes] = []
    result = FundingBindingTransactionMatch(binding.funding_txid, 1, binding.lineage_anchor_txid, 0)

    def checker(
        raw: bytes, observed: FundingBinding, signed: ContractTerms, *, keys: object
    ) -> FundingBindingTransactionMatch:
        assert observed == binding
        assert signed == terms
        assert keys is None
        received.append(raw)
        return result

    monkeypatch.setattr(core_tx_bytes, "check_funding_binding_transaction", checker)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    cookie = _cookie(tmp_path)
    with _server(_success, requests) as port:
        reader = RegtestCoreTransactionReader(port=port, cookie_path=cookie, network=network)
        assert not requests
        assert reader.fetch_binding_byte_match(binding, terms, keys=None) == result  # type: ignore[arg-type]
        cookie.write_text("__cookie__:rotated\n")
        assert reader.fetch_binding_byte_match(binding, terms, keys=None) == result  # type: ignore[arg-type]
        foreign = terms.model_copy(
            update={
                "network_identity": network.model_copy(update={"deployment_namespace": "different"})
            }
        )
        with pytest.raises(ValueError, match="full network"):
            reader.fetch_binding_byte_match(binding, foreign, keys=None)  # type: ignore[arg-type]
    assert received == [bytes.fromhex("02000000000100")] * 2
    assert [item["method"] for item in requests] == [
        "getblockchaininfo",
        "getblockhash",
        "getrawtransaction",
    ] * 2
    assert [item["params"] for item in requests[:3]] == [[], [0], [binding.funding_txid, False]]
    assert [item["id"] for item in requests[:3]] == [1, 2, 3]
    assert all(item["path"] == "/" and item["jsonrpc"] == "2.0" for item in requests)
    assert all(item["encoding"] == "identity" for item in requests)
    assert [requests[0]["auth"], requests[3]["auth"]] == [
        "Basic " + base64.b64encode(b"__cookie__:secret").decode(),
        "Basic " + base64.b64encode(b"__cookie__:rotated").decode(),
    ]


@pytest.mark.parametrize(
    "host", ["localhost", "10.0.0.1", "127.0.0.1@elsewhere", "127.0.0.1/wallet/x"]
)
def test_remote_or_wallet_endpoints_are_not_configurable(tmp_path: Path, host: str) -> None:
    _, _, network = _context()
    with pytest.raises(ValueError, match="loopback"):
        RegtestCoreTransactionReader(
            port=18443, host=host, cookie_path=tmp_path / "none", network=network
        )


@pytest.mark.parametrize(
    "cookie", ["", "name:secret", "__cookie__:", "__cookie__:x\ny", "__cookie__:" + "x" * 513]
)
def test_missing_or_bad_cookie_stops_before_network(tmp_path: Path, cookie: str) -> None:
    terms, binding, network = _context()
    path = _cookie(tmp_path, cookie)
    reader = RegtestCoreTransactionReader(port=18443, cookie_path=path, network=network)
    with pytest.raises(CoreAuthError) as caught:
        reader.fetch_binding_byte_match(binding, terms, keys=None)  # type: ignore[arg-type]
    assert caught.value.__cause__ is None
    assert "secret" not in str(caught.value)
    path.chmod(0o644)
    with pytest.raises(CoreAuthError):
        reader.fetch_binding_byte_match(binding, terms, keys=None)  # type: ignore[arg-type]
    path.chmod(0o600)
    path.unlink()
    path.symlink_to(tmp_path / "other")
    with pytest.raises(CoreAuthError):
        reader.fetch_binding_byte_match(binding, terms, keys=None)  # type: ignore[arg-type]
    path.unlink()
    target = tmp_path / "private-real-cookie"
    target.write_text("__cookie__:secret")
    target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(CoreAuthError):
        reader.fetch_binding_byte_match(binding, terms, keys=None)  # type: ignore[arg-type]


def test_fifo_cookie_never_blocks_before_file_type_check(tmp_path: Path) -> None:
    path = tmp_path / "core-fifo"
    os.mkfifo(path, 0o600)
    script = (
        "import sys\nfrom pathlib import Path\n"
        "from rill_provider.core_tx_bytes import _cookie, CoreAuthError\n"
        "try:\n    _cookie(Path(sys.argv[1]))\n"
        "except CoreAuthError:\n    sys.exit(0)\n"
        "sys.exit(1)\n"
    )
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and literal read-only probe
        [sys.executable, "-c", script, str(path)],
        capture_output=True,
        timeout=2,
        check=False,
    )
    assert completed.returncode == 0


def test_inactivity_timeout_and_slow_header_limitation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    terms, binding, network = _context()
    seen = 0

    def checker(*_args: object, **_kwargs: object) -> FundingBindingTransactionMatch:
        nonlocal seen
        seen += 1
        return FundingBindingTransactionMatch(
            binding.funding_txid, 1, binding.lineage_anchor_txid, 0
        )

    monkeypatch.setattr(core_tx_bytes, "check_funding_binding_transaction", checker)
    monkeypatch.setattr(core_tx_bytes, "READ_SECONDS", 1.0)
    with _server(_success, [], header_mode="stall") as port:
        reader = RegtestCoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network
        )
        with pytest.raises(CoreUnavailableError):
            reader.fetch_binding_byte_match(binding, terms, keys=None)  # type: ignore[arg-type]
    assert seen == 0
    with _server(_success, [], header_mode="trickle") as port:
        reader = RegtestCoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network
        )
        start = time.monotonic()
        try:
            match = reader.fetch_binding_byte_match(binding, terms, keys=None)  # type: ignore[arg-type]
        except CoreUnavailableError as error:
            raise AssertionError(f"trickled headers failed: {error.__context__!r}") from error
        assert match.funding_txid == binding.funding_txid
        assert time.monotonic() - start > core_tx_bytes.READ_SECONDS
    assert seen == 1


@pytest.mark.parametrize(
    "kind",
    [
        "wrong-chain",
        "wrong-genesis",
        "wrong-id",
        "duplicate",
        "invalid-hex",
        "unavailable",
        "unauthorized",
        "redirect",
        "oversize",
    ],
)
def test_bad_rpc_response_cannot_become_static_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    terms, binding, network = _context()
    calls = 0

    def must_not_check(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1

    monkeypatch.setattr(core_tx_bytes, "check_funding_binding_transaction", must_not_check)

    def broken(payload: dict[str, Any]) -> tuple[int, bytes]:  # noqa: PLR0911
        if kind == "unauthorized":
            return 401, b"private-password"
        if kind == "redirect":
            return 302, b"not followed"
        status, body = _success(payload)
        if kind == "wrong-chain" and payload["method"] == "getblockchaininfo":
            return status, body.replace(b"regtest", b"main")
        if kind == "wrong-genesis" and payload["method"] == "getblockhash":
            return status, body.replace(GENESIS.encode(), b"ff" * 32)
        if payload["method"] == "getrawtransaction":
            if kind == "wrong-id":
                return status, body.replace(b'"id": 3', b'"id": 9')
            if kind == "duplicate":
                return status, body.replace(b'"result": ', b'"result": "", "result": ')
            if kind == "invalid-hex":
                return status, body.replace(b"02000000000100", b"GG")
            if kind == "unavailable":
                return status, json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "error": {"code": -5, "message": "No such tx"},
                    }
                ).encode()
            if kind == "oversize":
                return status, b" " * (core_tx_bytes.MAX_RESPONSE_BYTES + 1)
        return status, body

    with _server(broken, []) as port:
        reader = RegtestCoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network
        )
        expected = (
            CoreAuthError
            if kind == "unauthorized"
            else (
                CoreUnavailableError if kind in {"redirect", "unavailable"} else CoreProtocolError
            )
        )
        with pytest.raises(expected) as caught:
            reader.fetch_binding_byte_match(binding, terms, keys=None)  # type: ignore[arg-type]
    assert calls == 0
    assert "private-password" not in str(caught.value)


def test_static_checker_rejection_is_never_recast_as_funding_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terms, binding, network = _context()

    def fail_match(*_args: object, **_kwargs: object) -> None:
        raise ValidationError("static byte mismatch")

    monkeypatch.setattr(core_tx_bytes, "check_funding_binding_transaction", fail_match)
    with _server(_success, []) as port:
        reader = RegtestCoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network
        )
        with pytest.raises(ValidationError, match="static byte mismatch"):
            reader.fetch_binding_byte_match(binding, terms, keys=None)  # type: ignore[arg-type]


def test_fetched_bytes_pass_real_core_static_checker_only(tmp_path: Path) -> None:
    terms, template, network = _context()
    fixture = json.loads((FIXTURES / "initial-btc-to-ln-v1.json").read_bytes())
    artifact = fixture["taproot_contract"]

    class Keys:
        def musig_internal_key(self, client: bytes, provider: bytes) -> tuple[bytes, int]:
            assert client.hex() == terms.client_contract_compressed_key
            assert provider.hex() == terms.provider_contract_compressed_key
            return bytes.fromhex(artifact["internal_xonly_key"]), artifact["internal_key_parity"]

        def musig_output_key(
            self, client: bytes, provider: bytes, tap_tweak: bytes
        ) -> tuple[bytes, int]:
            assert client.hex() == terms.client_contract_compressed_key
            assert provider.hex() == terms.provider_contract_compressed_key
            assert tap_tweak.hex() == artifact["tap_tweak"]
            return bytes.fromhex(artifact["output_xonly_key"]), artifact["output_key_parity"]

    script = bytes.fromhex(artifact["script_pubkey"])
    amount = int(terms.economics.contract_amount_sat)
    change = b"\x51\x20" + b"\x44" * 32
    raw = (
        b"\x02\x00\x00\x00\x01"
        + bytes.fromhex(template.lineage_anchor_txid)[::-1]
        + b"\x00\x00\x00\x00\x00\xfd\xff\xff\xff\x02"
        + (9_000).to_bytes(8, "little")
        + bytes([len(change)])
        + change
        + amount.to_bytes(8, "little")
        + bytes([len(script)])
        + script
        + b"\x00\x00\x00\x00"
    )
    txid = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
    binding = template.model_copy(update={"funding_txid": txid})

    def respond(payload: dict[str, Any]) -> tuple[int, bytes]:
        if payload["method"] != "getrawtransaction":
            return _success(payload)
        return 200, json.dumps(
            {"jsonrpc": "2.0", "id": payload["id"], "result": raw.hex()}
        ).encode()

    with _server(respond, []) as port:
        reader = RegtestCoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network
        )
        match = reader.fetch_binding_byte_match(binding, terms, keys=Keys())
        assert match.funding_txid == txid
        assert match.contract_vout == 1
        changed = binding.model_copy(update={"funding_txid": "88" * 32})
        with pytest.raises(ValidationError, match="transaction ID differs"):
            reader.fetch_binding_byte_match(changed, terms, keys=Keys())
