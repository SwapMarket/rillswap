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
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from rill_core.errors import ValidationError
from rill_core.settlement import (
    FundingBindingTransactionMatch,
    SignedFundingBinding,
    verify_static_signed_funding_binding_history,
)
from rill_core.wire.hashes import funding_binding_hash
from rill_core.wire.messages import ContractTerms, FundingBinding, HandshakeAccept, HandshakeInit
from rill_core.wire.types import NetworkIdentity

from rill_provider import core_tx_bytes
from rill_provider.core_tx_bytes import (
    CoreAuthError,
    CoreProtocolError,
    CoreTransactionReader,
    CoreTransactionUnknownError,
    CoreUnavailableError,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

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
        reader = CoreTransactionReader(port=port, cookie_path=cookie, network=network)
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
        CoreTransactionReader(port=18443, host=host, cookie_path=tmp_path / "none", network=network)


@pytest.mark.parametrize(
    "cookie", ["", "name:secret", "__cookie__:", "__cookie__:x\ny", "__cookie__:" + "x" * 513]
)
def test_missing_or_bad_cookie_stops_before_network(tmp_path: Path, cookie: str) -> None:
    terms, binding, network = _context()
    path = _cookie(tmp_path, cookie)
    reader = CoreTransactionReader(port=18443, cookie_path=path, network=network)
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
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        with pytest.raises(CoreUnavailableError):
            reader.fetch_binding_byte_match(binding, terms, keys=None)  # type: ignore[arg-type]
    assert seen == 0
    with _server(_success, [], header_mode="trickle") as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
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
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
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
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
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
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        match = reader.fetch_binding_byte_match(binding, terms, keys=Keys())
        assert match.funding_txid == txid
        assert match.contract_vout == 1
        changed = binding.model_copy(update={"funding_txid": "88" * 32})
        with pytest.raises(ValidationError, match="transaction ID differs"):
            reader.fetch_binding_byte_match(changed, terms, keys=Keys())


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 and RILL_CRYPTO_LIBRARY",
)
def test_static_signed_history_precedes_core_candidate_sample(tmp_path: Path) -> None:
    """Fixture composition only, never admission or a current-lineage claim."""
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native library

    terms, template, _ = _context()  # Hash-check pinned public synthetic fixture.
    fixture = json.loads((FIXTURES / "initial-btc-to-ln-v1.json").read_bytes())
    context = fixture["verification_context"]
    network = NetworkIdentity.model_validate(
        {
            "family": "bitcoin",
            "name": "regtest",
            "genesis_hash": GENESIS,
            "signet_challenge": None,
            "consensus_profile": "bitcoin-core-v30.0-regtest-default",
            "deployment_namespace": "rillswap-e2e-v1",
        }
    )
    trusted_provider = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    assert terms.network_identity == network
    script = bytes.fromhex(fixture["taproot_contract"]["script_pubkey"])
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
    requests: list[dict[str, Any]] = []

    def respond(payload: dict[str, Any]) -> tuple[int, bytes]:
        if payload["method"] == "getrawtransaction":
            return 200, json.dumps(
                {"jsonrpc": "2.0", "id": payload["id"], "result": raw.hex()}
            ).encode()
        return _candidate_reply(payload, binding)

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        client_secret = (2).to_bytes(32, "big")
        assert crypto.public_key(client_secret)[1:].hex() == context["client_session_xonly_key"]
        signature = crypto.schnorr_sign(
            client_secret, funding_binding_hash(binding), b"\x33" * 32
        ).hex()

        def verify(funder_signature: str) -> None:
            verify_static_signed_funding_binding_history(
                terms=terms,
                handshake_init=HandshakeInit.model_validate_json(
                    json.dumps(context["handshake_init"])
                ),
                handshake_accept=HandshakeAccept.model_validate_json(
                    json.dumps(context["handshake_accept"])
                ),
                provider_identity_signature=context["provider_identity_signature"],
                provider_terms_signature=context["provider_terms_signature"],
                client_acceptance_signature=context["client_acceptance_signature"],
                signed_bindings=(SignedFundingBinding(binding, funder_signature),),
                expected_provider_identity=trusted_provider,
                expected_network=network,
                crypto=crypto,
            )

        with _server(respond, requests) as port:
            reader = CoreTransactionReader(
                port=port, cookie_path=_cookie(tmp_path), network=network
            )
            tampered = signature[:-2] + ("00" if signature[-2:] != "00" else "01")
            with pytest.raises(ValidationError, match="invalid static signed funding declaration"):
                verify(tampered)
            assert requests == []
            verify(signature)
            observed = reader.observe_candidate_outpoint(binding, terms, keys=crypto)
    assert observed.static_match == FundingBindingTransactionMatch(
        txid, binding.contract_vout, binding.lineage_anchor_txid, binding.lineage_anchor_vout
    )
    assert [item["method"] for item in requests] == [
        "getblockchaininfo",
        "getblockhash",
        "getrawtransaction",
        "gettxout",
        "getblockhash",
        "getrawtransaction",
        "getblockchaininfo",
    ]


def _candidate_reply(  # noqa: PLR0912, PLR0915 - explicit malformed Core response variants
    payload: dict[str, Any], binding: FundingBinding, *, change: str = "none"
) -> tuple[int, bytes]:
    tip = "aa" * 32
    info: dict[str, Any] = {
        "chain": "regtest",
        "blocks": 105,
        "bestblockhash": tip,
        "initialblockdownload": False,
    }
    output: dict[str, Any] = {
        "bestblock": tip,
        "confirmations": 3,
        "coinbase": False,
        "value": int(binding.contract_value_sat) / 100_000_000,
        "scriptPubKey": {"hex": binding.contract_script_pubkey},
    }
    if change == "tip" and payload["id"] == 7:
        info["bestblockhash"] = "bb" * 32
    if change == "height" and payload["id"] == 7:
        info["blocks"] = 106
    if change == "unsynced":
        info["initialblockdownload"] = True
    if change == "script":
        output["scriptPubKey"]["hex"] = "51" + "20" + "44" * 32
    if change == "value":
        output["value"] = 0.00000001
    if change == "fractional-sat":
        output["value"] = 0.001010001
    if change == "bestblock":
        output["bestblock"] = "bb" * 32
    if change == "boolean-confirms":
        output["confirmations"] = True
    if change == "excess-confirmations":
        output["confirmations"] = 106
    if change in ("tip-inclusion", "tip-inclusion-mismatch"):
        output["confirmations"] = 1
    if change == "coinbase":
        output["coinbase"] = True
    if change == "missing-coinbase":
        output.pop("coinbase")
    if change == "malformed-coinbase":
        output["coinbase"] = 0
    if change == "tiny-fraction":
        output["value"] = Decimal("0.001010000000000000000000000000000000000001")
    if change == "huge-exponent":
        output["value"] = Decimal("1e1000000")
    if change == "tiny-exponent":
        output["value"] = Decimal("1e-1000000")
    if change == "unrepresentable-exponent":
        output["value"] = "UNREPRESENTABLE_EXPONENT_PLACEHOLDER"
    block_hash = (
        tip if payload["method"] == "getblockhash" and payload["params"] == [105] else "cc" * 32
    )
    if change == "bad-inclusion-hash" and payload["id"] == 5:
        block_hash = "CC" * 32
    if change == "tip-inclusion-mismatch" and payload["id"] == 5:
        block_hash = "bb" * 32
    if change == "block-bytes-differ" and payload["id"] == 6:
        transaction = "01000000000100"
    else:
        transaction = "02000000000100"
    result: object = {
        "getblockchaininfo": info,
        "getblockhash": GENESIS if payload["params"] == [0] else block_hash,
        "getrawtransaction": transaction,
        "gettxout": output if change != "null" else None,
    }[payload["method"]]
    if change == "block-not-found" and payload["id"] == 6:
        return 200, json.dumps(
            {
                "jsonrpc": "2.0",
                "id": payload["id"],
                "error": {"code": -5, "message": "not found"},
            }
        ).encode()
    if isinstance(output.get("value"), Decimal):
        # Preserve the literal JSON numeric token; serializing through float
        # would erase exactly the malformed precision being tested.
        encoded = json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}, default=str)
        quoted = json.dumps(str(output["value"]))
        return 200, encoded.replace(f'"value": {quoted}', f'"value": {output["value"]}').encode()
    if change == "unrepresentable-exponent":
        encoded = json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result})
        return 200, encoded.replace(
            '"UNREPRESENTABLE_EXPONENT_PLACEHOLDER"',
            "1e99999999999999999999999999999999999999999999999",
        ).encode()
    return 200, json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}).encode()


def test_candidate_is_a_named_tip_utxo_sample_not_lineage_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    terms, binding, network = _context()
    match = FundingBindingTransactionMatch(
        binding.funding_txid,
        binding.contract_vout,
        binding.lineage_anchor_txid,
        binding.lineage_anchor_vout,
    )
    calls: list[bytes] = []

    def checker(raw: bytes, *_args: object, **_kwargs: object) -> FundingBindingTransactionMatch:
        calls.append(raw)
        return match

    monkeypatch.setattr(core_tx_bytes, "check_funding_binding_transaction", checker)
    requests: list[dict[str, Any]] = []
    with _server(lambda payload: _candidate_reply(payload, binding), requests) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        result = reader.observe_candidate_outpoint(binding, terms, keys=None)  # type: ignore[arg-type]
    assert calls == [bytes.fromhex("02000000000100")]
    assert result.network_identity == network
    assert result.static_match == match
    assert result.tip_hash == "aa" * 32
    assert result.tip_height == 105
    assert result.chain_only_confirmations == 3
    assert result.inclusion_height == 103
    assert result.inclusion_block_hash == "cc" * 32
    assert [request["method"] for request in requests] == [
        "getblockchaininfo",
        "getblockhash",
        "getrawtransaction",
        "gettxout",
        "getblockhash",
        "getrawtransaction",
        "getblockchaininfo",
    ]
    assert requests[3]["params"] == [binding.funding_txid, binding.contract_vout, False]
    assert requests[4]["params"] == [103]
    assert requests[5]["params"] == [binding.funding_txid, False, "cc" * 32]
    assert len(requests) == 7


def test_candidate_tip_block_inclusion_is_still_not_lineage_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terms, binding, network = _context()
    monkeypatch.setattr(
        core_tx_bytes,
        "check_funding_binding_transaction",
        lambda *_args, **_kwargs: FundingBindingTransactionMatch(
            binding.funding_txid,
            binding.contract_vout,
            binding.lineage_anchor_txid,
            binding.lineage_anchor_vout,
        ),
    )
    requests: list[dict[str, Any]] = []
    with _server(
        lambda payload: _candidate_reply(payload, binding, change="tip-inclusion"), requests
    ) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        result = reader.observe_candidate_outpoint(binding, terms, keys=None)  # type: ignore[arg-type]
    assert result.inclusion_height == 105
    assert result.inclusion_block_hash == "aa" * 32
    assert result.__class__ is core_tx_bytes.CandidateFundingOutpoint
    assert len(requests) == 7


@pytest.mark.parametrize(
    ("change", "error_type"),
    [
        ("tip", CoreUnavailableError),
        ("height", CoreUnavailableError),
        ("null", CoreUnavailableError),
        ("bestblock", CoreUnavailableError),
        ("unsynced", CoreProtocolError),
        ("script", CoreProtocolError),
        ("value", CoreProtocolError),
        ("fractional-sat", CoreProtocolError),
        ("boolean-confirms", CoreProtocolError),
        ("excess-confirmations", CoreProtocolError),
        ("coinbase", CoreProtocolError),
        ("missing-coinbase", CoreProtocolError),
        ("malformed-coinbase", CoreProtocolError),
        ("tiny-fraction", CoreProtocolError),
        ("huge-exponent", CoreProtocolError),
        ("tiny-exponent", CoreProtocolError),
        ("unrepresentable-exponent", CoreProtocolError),
        ("bad-inclusion-hash", CoreProtocolError),
        ("tip-inclusion-mismatch", CoreProtocolError),
        ("block-bytes-differ", CoreProtocolError),
        ("block-not-found", CoreUnavailableError),
    ],
)
def test_candidate_unknown_or_mismatched_chain_never_returns_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str, error_type: type[Exception]
) -> None:
    terms, binding, network = _context()
    monkeypatch.setattr(
        core_tx_bytes,
        "check_funding_binding_transaction",
        lambda *_args, **_kwargs: FundingBindingTransactionMatch(
            binding.funding_txid,
            binding.contract_vout,
            binding.lineage_anchor_txid,
            binding.lineage_anchor_vout,
        ),
    )
    requests: list[dict[str, Any]] = []
    with _server(
        lambda payload: _candidate_reply(payload, binding, change=change), requests
    ) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        with pytest.raises(error_type):
            reader.observe_candidate_outpoint(binding, terms, keys=None)  # type: ignore[arg-type]
    assert len(requests) in (1, 4, 5, 6, 7)
    assert [item["method"] for item in requests].count("gettxout") <= 1


def test_tip_height_checks_chain_and_genesis(tmp_path: Path) -> None:
    _terms, _binding, network = _context()
    tip = {
        "chain": "regtest",
        "bestblockhash": "11" * 32,
        "blocks": 1234,
        "initialblockdownload": False,
    }

    def reply(genesis: str) -> Any:  # noqa: ANN401
        def answer(payload: dict[str, Any]) -> tuple[int, bytes]:
            result = tip if payload["method"] == "getblockchaininfo" else genesis
            return 200, json.dumps(
                {"jsonrpc": "2.0", "id": payload["id"], "result": result}
            ).encode()

        return answer

    requests: list[dict[str, Any]] = []
    cookie = _cookie(tmp_path)
    with _server(reply(GENESIS), requests) as port:
        reader = CoreTransactionReader(port=port, cookie_path=cookie, network=network)
        assert reader.tip_height() == 1234
    with _server(reply("22" * 32), requests) as port:
        reader = CoreTransactionReader(port=port, cookie_path=cookie, network=network)
        with pytest.raises(core_tx_bytes.CoreProtocolError, match="genesis"):
            reader.tip_height()


def _rpc_reply(
    result: object = None, error: dict[str, Any] | None = None
) -> Callable[[dict[str, Any]], tuple[int, bytes]]:
    def respond(payload: dict[str, Any]) -> tuple[int, bytes]:
        body: dict[str, Any] = {"jsonrpc": "2.0", "id": payload["id"]}
        body |= {"error": error} if error is not None else {"result": result}
        return 200, json.dumps(body).encode()

    return respond


def test_broadcast_is_exact_and_idempotent(tmp_path: Path) -> None:
    _, _, network = _context()
    requests: list[dict[str, Any]] = []
    txid = "ab" * 32
    with _server(_rpc_reply(txid), requests) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        assert reader.broadcast(b"\x02\x00", txid) == txid
    assert (requests[0]["method"], requests[0]["params"]) == ("sendrawtransaction", ["0200"])
    with _server(_rpc_reply(error={"code": -27, "message": "already"}), []) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        assert reader.broadcast(b"\x02\x00", txid) == txid  # already in the chain
    with _server(_rpc_reply(error={"code": -26, "message": "rejected"}), []) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        with pytest.raises(CoreUnavailableError):
            reader.broadcast(b"\x02\x00", txid)
    with _server(_rpc_reply("cd" * 32), []) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        with pytest.raises(CoreProtocolError):
            reader.broadcast(b"\x02\x00", txid)


def test_confirmations_counts_mempool_as_zero(tmp_path: Path) -> None:
    _, _, network = _context()
    txid = "ab" * 32
    for result, expected in (({"txid": txid}, 0), ({"txid": txid, "confirmations": 4}, 4)):
        with _server(_rpc_reply(result), []) as port:
            reader = CoreTransactionReader(
                port=port, cookie_path=_cookie(tmp_path), network=network
            )
            assert reader.confirmations(txid) == expected
    with _server(_rpc_reply({"txid": "cd" * 32}), []) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        with pytest.raises(CoreProtocolError):
            reader.confirmations(txid)


@pytest.mark.parametrize(
    ("index", "expected"),
    [
        ({"txindex": {"synced": True, "best_block_height": 10}}, CoreTransactionUnknownError),
        ({"txindex": {"synced": False, "best_block_height": 3}}, CoreUnavailableError),
        ({}, CoreUnavailableError),
    ],
)
def test_unknown_transaction_is_absence_evidence_only_with_a_synced_txindex(
    tmp_path: Path, index: dict[str, Any], expected: type[Exception]
) -> None:
    _, _, network = _context()
    requests: list[dict[str, Any]] = []

    def respond(payload: dict[str, Any]) -> tuple[int, bytes]:
        if payload["method"] == "getrawtransaction":
            return _rpc_reply(error={"code": -5, "message": "No such tx"})(payload)
        assert payload["method"] == "getindexinfo"
        return _rpc_reply(index)(payload)

    with _server(respond, requests) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        with pytest.raises(expected):
            reader.confirmations("ab" * 32)
    assert [r["method"] for r in requests] == ["getrawtransaction", "getindexinfo"]


def test_outpoint_unspent_reads_the_confirmed_chain_only(tmp_path: Path) -> None:
    _, _, network = _context()
    requests: list[dict[str, Any]] = []
    with _server(_rpc_reply({"value": 1, "confirmations": 3}), requests) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        assert reader.outpoint_unspent("ab" * 32, 1) is True
    assert (requests[0]["method"], requests[0]["params"]) == ("gettxout", ["ab" * 32, 1, False])
    with _server(_rpc_reply(None), []) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        assert reader.outpoint_unspent("ab" * 32, 1) is False
    with _server(_rpc_reply(error={"code": -1, "message": "help"}), []) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        with pytest.raises(CoreUnavailableError):
            reader.outpoint_unspent("ab" * 32, 1)
