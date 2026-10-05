"""Historical recognition evidence, not current funds or destination-key custody."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any

import pytest
from rill_core.networks import REGTEST_CONSENSUS_PROFILE
from rill_core.wire.types import NetworkIdentity

from rill_cli import wallet_rpc as module
from rill_cli.wallet_rpc import HistoricalWalletOutput, WalletRpc, WalletRpcError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

NETWORK = NetworkIdentity(
    family="bitcoin",
    name="regtest",
    genesis_hash="0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    signet_challenge=None,
    consensus_profile=REGTEST_CONSENSUS_PROFILE,
    deployment_namespace="wallet-history-fixture",
)
SCRIPT = bytes.fromhex("5120" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
TIP_HASH, BLOCK_HASH = "a" * 64, "b" * 64


def transaction(outputs: tuple[tuple[int, bytes], ...]) -> bytes:
    return (
        b"\x02\x00\x00\x00\x01"
        + b"\x11" * 32
        + b"\x01\x00\x00\x00\x00"
        + b"\xff" * 4
        + bytes([len(outputs)])
        + b"".join(
            value.to_bytes(8, "little") + bytes([len(script)]) + script for value, script in outputs
        )
        + b"\x00" * 4
    )


class HistoryRpc:
    def __init__(self, tmp_path: Path) -> None:
        self.raw = transaction(((0, b"\x6a"), (100100, SCRIPT)))
        self.txid = hashlib.sha256(hashlib.sha256(self.raw).digest()).digest()[::-1].hex()
        self.record: dict[str, Any] = {
            "txid": self.txid,
            "hex": self.raw.hex(),
            "confirmations": 3,
            "blockheight": 98,
            "blockhash": BLOCK_HASH,
        }
        self.after_record: dict[str, Any] | None = None
        self.info: dict[str, Any] = {
            "chain": "regtest",
            "blocks": 100,
            "bestblockhash": TIP_HASH,
            "initialblockdownload": False,
        }
        self.after_info: dict[str, Any] | None = None
        self.decoded: dict[str, Any] = {
            "type": "witness_v1_taproot",
            "address": "bcrt1p-synthetic-script",
        }
        self.recognition: dict[str, Any] = {"ismine": True, "scriptPubKey": SCRIPT.hex()}
        self.hashes: dict[int, str] = {
            0: NETWORK.genesis_hash,
            98: BLOCK_HASH,
            100: TIP_HASH,
            101: "c" * 64,
        }
        self.after_hashes: dict[int, str] | None = None
        self.envelope: bytes | None = None
        self.calls: list[dict[str, Any]] = []
        self.wall_end: float | None = None
        self.elapsed: float | None = None
        self.counts: dict[str, int] = {}
        self.cookie = tmp_path / "core.cookie"
        self.cookie.write_text("__cookie__:synthetic-test-key")
        self.cookie.chmod(0o600)
        state = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                state.calls.append({"path": self.path, **request})
                method = request["method"]
                state.counts[method] = state.counts.get(method, 0) + 1
                result: object
                if method == "getblockchaininfo":
                    result = (
                        state.info
                        if state.counts[method] == 1 or state.after_info is None
                        else state.after_info
                    )
                elif method == "gettransaction":
                    result = (
                        state.record
                        if state.counts[method] == 1 or state.after_record is None
                        else state.after_record
                    )
                elif method == "getblockhash":
                    hashes = (
                        state.hashes | (state.after_hashes or {})
                        if state.counts.get("getblockchaininfo", 0) >= 2
                        else state.hashes
                    )
                    result = hashes.get(request["params"][0], "f" * 64)
                elif method == "decodescript":
                    result = state.decoded
                elif method == "getaddressinfo":
                    result = state.recognition
                else:
                    result = None
                payload = (
                    state.envelope
                    if state.envelope is not None
                    else json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()
                )
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.wallet = WalletRpc(
            port=self.server.server_port,
            cookie_path=self.cookie,
            wallet="recognition",
            network=NETWORK,
        )

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        assert not self.thread.is_alive()

    def observe(self) -> HistoricalWalletOutput:
        return self.wallet.observe_historical_wallet_output(self.txid, SCRIPT)


@pytest.fixture
def core(tmp_path: Path) -> Iterator[HistoryRpc]:
    state = HistoryRpc(tmp_path)
    try:
        yield state
    finally:
        state.close()


def refused(core: HistoryRpc) -> None:
    with pytest.raises(WalletRpcError) as failure:
        core.observe()
    assert str(failure.value) == "historical Core wallet output unavailable"
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert not any(call["method"] in module.WALLET_EFFECTS for call in core.calls)


def test_historical_wallet_recognition_returns_exact_nonzero_index_and_literal_value(
    core: HistoryRpc,
) -> None:
    evidence = core.observe()
    assert evidence.network == NETWORK
    assert (evidence.txid, evidence.vout, evidence.value_sat, evidence.script_pubkey) == (
        core.txid,
        1,
        100100,
        SCRIPT,
    )
    assert (evidence.confirmations, evidence.block_height, evidence.block_hash) == (
        3,
        98,
        BLOCK_HASH,
    )
    assert evidence.completed_at >= evidence.started_at
    assert "gettxout" not in [call["method"] for call in core.calls]
    assert "getwalletinfo" not in [call["method"] for call in core.calls]
    assert not any(call["method"] in module.WALLET_EFFECTS for call in core.calls)
    for call in core.calls:
        expected_path = (
            "/wallet/recognition" if call["method"] in {"gettransaction", "getaddressinfo"} else "/"
        )
        assert call["path"] == expected_path


def test_public_only_recognition_and_historical_spent_state_are_not_key_custody(
    core: HistoryRpc,
) -> None:
    core.recognition.update(
        ismine=True, iswatchonly=False, solvable=True, desc="rawtr(public-only)"
    )
    core.record.update(spent=True)  # not a Core gettransaction field or eligibility input
    evidence = core.observe()
    assert evidence.value_sat == 100100
    assert not hasattr(evidence, "owned")
    assert not hasattr(evidence, "spendable_msat")
    assert not hasattr(evidence, "private_keys_enabled")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("txid", "f" * 64),
        ("hex", "00"),
        ("hex", "not-hex"),
        ("confirmations", 0),
        ("confirmations", -1),
        ("confirmations", True),
        ("confirmations", 3.0),
        ("blockheight", 0),
        ("blockheight", 101),
        ("blockheight", True),
        ("blockhash", "f" * 64),
    ],
)
def test_unconfirmed_conflicted_unknown_or_substituted_historical_records_refuse(
    core: HistoryRpc, field: str, value: object
) -> None:
    core.record[field] = value
    refused(core)


@pytest.mark.parametrize("field", ["txid", "script"])
def test_invalid_outpoint_or_treasury_script_never_reads_core(core: HistoryRpc, field: str) -> None:
    with pytest.raises(WalletRpcError):
        core.wallet.observe_historical_wallet_output(
            "UPPERCASE" if field == "txid" else core.txid,
            b"\x00\x14" + b"x" * 20 if field == "script" else SCRIPT,
        )
    assert not core.calls


def test_missing_cookie_detaches_private_local_error_without_rpc(core: HistoryRpc) -> None:
    core.cookie.unlink()
    refused(core)
    assert not core.calls


@pytest.mark.parametrize(
    "fault",
    [
        "txid_bytes",
        "missing_script",
        "multiple_scripts",
        "zero_value",
        "record_changed",
        "block_changed",
        "unrecognized",
        "coerced_recognition",
        "address_script",
        "wrapped_address",
    ],
)
def test_transaction_and_wallet_script_correspondence_is_unambiguous(
    core: HistoryRpc, fault: str
) -> None:
    if fault == "txid_bytes":
        core.record["hex"] = transaction(((1, SCRIPT),)).hex()
    elif fault == "missing_script":
        core.raw = transaction(((1, b"\x6a"),))
    elif fault == "multiple_scripts":
        core.raw = transaction(((1, SCRIPT), (1, SCRIPT)))
    elif fault == "zero_value":
        core.raw = transaction(((0, SCRIPT),))
    elif fault == "record_changed":
        core.after_record = core.record | {"hex": transaction(((1, SCRIPT),)).hex()}
    elif fault == "block_changed":
        core.after_record = core.record | {"blockhash": "f" * 64}
    elif fault == "unrecognized":
        core.recognition["ismine"] = False
    elif fault == "coerced_recognition":
        core.recognition["ismine"] = 1
    elif fault == "address_script":
        core.recognition["scriptPubKey"] = "5120" + "f" * 64
    else:
        core.decoded = {"type": "witness_v1_taproot", "segwit": {"address": "wrapped"}}
    if fault in {"missing_script", "multiple_scripts", "zero_value"}:
        core.txid = hashlib.sha256(hashlib.sha256(core.raw).digest()).digest()[::-1].hex()
        core.record.update(hex=core.raw.hex(), txid=core.txid)
    refused(core)


@pytest.mark.parametrize(
    "fault",
    ["chain", "genesis", "ibd", "rollback", "sameheight_fork", "advancing_fork", "block_depth"],
)
def test_chain_attestation_and_sampled_branch_consistency_refuse_ambiguity(
    core: HistoryRpc, fault: str
) -> None:
    if fault == "chain":
        core.info["chain"] = "signet"
    elif fault == "genesis":
        core.hashes[0] = "f" * 64
    elif fault == "ibd":
        core.info["initialblockdownload"] = True
    elif fault == "rollback":
        core.after_info = core.info | {"blocks": 99, "bestblockhash": "c" * 64}
        core.hashes[99] = "c" * 64
    elif fault == "sameheight_fork":
        core.after_info = core.info | {"bestblockhash": "c" * 64}
        core.after_hashes = {100: "c" * 64}
    elif fault == "advancing_fork":
        core.after_info = core.info | {"blocks": 101, "bestblockhash": "c" * 64}
        core.after_hashes = {100: "d" * 64}
    else:
        core.record["blockheight"] = 101
        core.record["blockhash"] = "c" * 64
    refused(core)


def test_advancing_tip_and_wallet_depth_use_original_chain_floor(core: HistoryRpc) -> None:
    core.after_info = core.info | {"blocks": 101, "bestblockhash": "c" * 64}
    core.record["confirmations"] = 10
    core.after_record = core.record | {"confirmations": 11}
    assert core.observe().confirmations == 3


@pytest.mark.parametrize(
    "payload",
    [
        b'{"jsonrpc":"2.0","id":true,"result":{}}',
        b'{"jsonrpc":"2.0","id":2,"result":{}}',
        b'{"id":1,"result":{}}',
        b'{"jsonrpc":"2.0","id":1,"id":1,"result":{}}',
        b'{"jsonrpc":"2.0","id":1,"result":{"x":1,"x":2}}',
        b'{"jsonrpc":"2.0","id":1,"result":NaN}',
        b'{"jsonrpc":"2.0","id":1,"error":{"code":-5,"message":"SECRET_CANARY"}}',
    ],
)
def test_strict_response_envelope_and_private_error_detachment(
    core: HistoryRpc, payload: bytes
) -> None:
    core.envelope = payload
    refused(core)


@pytest.mark.parametrize("fault", ["wall_rollback", "late_cleanup"])
def test_whole_acquisition_acceptance_refuses_clock_rollback_or_late_cleanup(
    core: HistoryRpc, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    real_call = core.wallet._call  # noqa: SLF001 - full transport/cleanup stays real
    times = [1000.0]
    elapsed = [10.0]
    monkeypatch.setattr(time, "time", lambda: times[0])
    monkeypatch.setattr(time, "monotonic", lambda: elapsed[0])

    def call(method: str, *args: object, **kwargs: Any) -> Any:  # noqa: ANN401 - exact original private transport wrapper
        result = real_call(method, *args, **kwargs)
        if len(core.calls) == 13:
            if fault == "wall_rollback":
                times[0] = 999.0
            else:
                elapsed[0] = 20.0
        return result

    monkeypatch.setattr(core.wallet, "_call", call)
    refused(core)


@pytest.mark.parametrize("budget", [0, -1, True, float("inf"), float("nan"), 31])
def test_invalid_budget_refuses_before_any_core_request(core: HistoryRpc, budget: float) -> None:
    with pytest.raises(WalletRpcError):
        core.wallet.observe_historical_wallet_output(core.txid, SCRIPT, deadline_seconds=budget)
    assert not core.calls
