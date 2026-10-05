"""Block-qualified historical byte facts, not live UTXOs or claim authority."""

from __future__ import annotations

import hashlib
import json
import time
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from rill_core.networks import REGTEST_CONSENSUS_PROFILE
from rill_core.wire.types import NetworkIdentity

from rill_provider.core_tx_bytes import (
    CoreHistoricalTransaction,
    CoreProtocolError,
    CoreTransactionReader,
    CoreUnavailableError,
)

if TYPE_CHECKING:
    from pathlib import Path
    from types import TracebackType

NETWORK = NetworkIdentity(
    family="bitcoin",
    name="regtest",
    genesis_hash="0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    signet_challenge=None,
    consensus_profile=REGTEST_CONSENSUS_PROFILE,
    deployment_namespace="block-history-fixture",
)
RAW = (
    b"\x02\x00\x00\x00\x01"
    + b"\x11" * 32
    + b"\x00" * 5
    + b"\xff" * 4
    + b"\x01"
    + (1000).to_bytes(8, "little")
    + b"\x01\x6a"
    + b"\x00" * 4
)
TXID = hashlib.sha256(hashlib.sha256(RAW).digest()).digest()[::-1].hex()
BLOCK_HASH, TIP_HASH = "a" * 64, "b" * 64
REAL_CLIENT = httpx.Client


class Harness:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.info: dict[str, Any] = {
            "chain": "regtest",
            "blocks": 100,
            "bestblockhash": TIP_HASH,
            "initialblockdownload": False,
        }
        self.after_info: dict[str, Any] | None = None
        self.hashes = {
            0: NETWORK.genesis_hash,
            98: BLOCK_HASH,
            99: "c" * 64,
            100: TIP_HASH,
            101: "d" * 64,
        }
        self.after_hashes: dict[int, str] = {}
        self.raw: object = RAW.hex()
        self.error: dict[str, object] | None = None
        self.calls: list[dict[str, Any]] = []
        self.info_count = 0
        self.cookie = tmp_path / "core.cookie"
        self.cookie.write_text("__cookie__:synthetic-test-token")
        self.cookie.chmod(0o600)
        self.reader = CoreTransactionReader(
            port=18443, cookie_path=self.cookie, network=NETWORK, wallet="not-used"
        )
        self.close_error = False
        self.closed = False
        self.wall, self.monotonic = 1000.0, 100.0
        self.cleanup_elapsed, self.cleanup_wall = 0.0, 0.0
        monkeypatch.setattr(time, "time", lambda: self.wall)
        monkeypatch.setattr(time, "monotonic", lambda: self.monotonic)
        state = self

        def respond(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/"
            call = json.loads(request.content)
            state.calls.append(call)
            method = call["method"]
            if method == "getblockchaininfo":
                state.info_count += 1
                result: object = (
                    state.info
                    if state.info_count == 1 or state.after_info is None
                    else state.after_info
                )
            elif method == "getblockhash":
                values = (
                    state.hashes | state.after_hashes if state.info_count >= 2 else state.hashes
                )
                result = values[call["params"][0]]
            elif method == "getrawtransaction":
                assert call["params"] == [TXID, False, BLOCK_HASH]
                result = state.raw
                if state.error is not None:
                    return httpx.Response(
                        200,
                        stream=httpx.ByteStream(
                            json.dumps(
                                {"jsonrpc": "2.0", "id": call["id"], "error": state.error}
                            ).encode()
                        ),
                    )
            else:
                raise AssertionError("unexpected observation method")
            return httpx.Response(
                200,
                stream=httpx.ByteStream(
                    json.dumps({"jsonrpc": "2.0", "id": call["id"], "result": result}).encode()
                ),
            )

        class Client(REAL_CLIENT):
            def __init__(self, **kwargs: Any) -> None:  # noqa: ANN401 - actual client with deterministic transport
                super().__init__(transport=httpx.MockTransport(respond), **kwargs)

            def __exit__(
                self,
                exc_type: type[BaseException] | None = None,
                exc_value: BaseException | None = None,
                traceback: TracebackType | None = None,
            ) -> None:
                super().__exit__(exc_type, exc_value, traceback)
                state.closed = True
                state.monotonic += state.cleanup_elapsed
                state.wall += state.cleanup_wall
                if state.close_error:
                    raise RuntimeError("SECRET_CANARY")

        monkeypatch.setattr(httpx, "Client", Client)

    def observe(self) -> CoreHistoricalTransaction:
        return self.reader.observe_block_transaction(TXID, block_height=98, block_hash=BLOCK_HASH)


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    return Harness(tmp_path, monkeypatch)


def refused(harness: Harness) -> None:
    with pytest.raises(CoreUnavailableError) as failure:
        harness.observe()
    assert str(failure.value) == "Core historical transaction acquisition unavailable"
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert all(
        call["method"] in {"getblockchaininfo", "getblockhash", "getrawtransaction"}
        for call in harness.calls
    )


def test_observation_returns_exact_bytes_and_sampled_context_without_wallet_or_utxo(
    harness: Harness,
) -> None:
    result = harness.observe()
    assert result.raw_transaction == RAW
    assert result.txid == TXID
    assert result.configured_network == NETWORK
    assert (result.block_height, result.block_hash, result.minimum_sampled_confirmations) == (
        98,
        BLOCK_HASH,
        3,
    )
    assert (result.tip_before_height, result.tip_before_hash) == (100, TIP_HASH)
    assert (result.tip_after_height, result.tip_after_hash) == (100, TIP_HASH)
    assert result.started_at == result.completed_at == 1000
    assert harness.closed
    assert len([call for call in harness.calls if call["method"] == "getrawtransaction"]) == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("txid", None),
        ("txid", "A" * 64),
        ("block_hash", None),
        ("block_hash", "A" * 64),
        ("block_height", None),
        ("block_height", True),
        ("block_height", 0),
        ("block_height", -1),
        ("deadline_seconds", 0),
        ("deadline_seconds", True),
        ("deadline_seconds", float("inf")),
        ("deadline_seconds", 11),
        ("deadline_seconds", 10**1000),
    ],
)
def test_absent_partial_or_invalid_hint_never_observes_or_discovers(
    harness: Harness, field: str, value: object
) -> None:
    arguments: dict[str, Any] = {
        "txid": TXID,
        "block_height": 98,
        "block_hash": BLOCK_HASH,
        "deadline_seconds": 10,
    } | {field: value}
    with pytest.raises(CoreProtocolError):
        harness.reader.observe_block_transaction(**arguments)
    assert not harness.calls


@pytest.mark.parametrize(
    "value", [None, True, "", "00", "not-hex", RAW.hex().upper(), RAW.hex() + "00", "00" * 100001]
)
def test_malformed_or_unsupported_raw_bytes_never_prove_absence(
    harness: Harness, value: object
) -> None:
    harness.raw = value
    refused(harness)


@pytest.mark.parametrize(
    "fault",
    [
        "chain",
        "genesis",
        "ibd",
        "tip_hash",
        "wrong_hint",
        "rollback",
        "sameheight_fork",
        "advancing_fork",
        "changed_block",
        "wrong_txid",
    ],
)
def test_backend_hint_identifier_and_observed_branch_mismatches_refuse(
    harness: Harness, fault: str
) -> None:
    if fault == "chain":
        harness.info["chain"] = "main"
    elif fault == "genesis":
        harness.hashes[0] = "f" * 64
    elif fault == "ibd":
        harness.info["initialblockdownload"] = True
    elif fault == "tip_hash":
        harness.hashes[100] = "f" * 64
    elif fault == "wrong_hint":
        harness.hashes[98] = "f" * 64
    elif fault == "rollback":
        harness.after_info = harness.info | {"blocks": 99, "bestblockhash": "c" * 64}
    elif fault == "sameheight_fork":
        harness.after_info = harness.info | {"bestblockhash": "c" * 64}
        harness.after_hashes[100] = "c" * 64
    elif fault == "advancing_fork":
        harness.after_info = harness.info | {"blocks": 101, "bestblockhash": "d" * 64}
        harness.after_hashes[100] = "f" * 64
    elif fault == "changed_block":
        harness.after_hashes[98] = "f" * 64
    else:
        harness.raw = RAW[:-4].hex() + "01000000"
    refused(harness)


def test_advancing_tip_uses_minimum_sampled_depth_not_continuous_confirmation_claim(
    harness: Harness,
) -> None:
    harness.after_info = harness.info | {"blocks": 101, "bestblockhash": "d" * 64}
    result = harness.observe()
    assert result.tip_after_height == 101
    assert result.minimum_sampled_confirmations == 3


@pytest.mark.parametrize(
    "fault",
    ["unknown", "pruned", "missing_cookie", "close_error", "late_cleanup", "rollback_clock"],
)
def test_unavailable_private_transport_cleanup_and_time_errors_are_detached(
    harness: Harness, fault: str
) -> None:
    if fault == "unknown":
        harness.error = {"code": -5, "message": "SECRET_CANARY"}
    elif fault == "pruned":
        harness.error = {"code": -1, "message": "SECRET_CANARY"}
    elif fault == "missing_cookie":
        harness.cookie.unlink()
    elif fault == "close_error":
        harness.close_error = True
    elif fault == "late_cleanup":
        harness.cleanup_elapsed = 10
    else:
        harness.cleanup_wall = -1
    refused(harness)
    if fault in {"close_error", "late_cleanup", "rollback_clock"}:
        assert harness.closed
