"""Known UTXO coordinates, no discovery, wallet lookup or funding authority."""

from __future__ import annotations

import hashlib
import json
import os
import time
import warnings
from importlib import import_module
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import httpx
import pytest
from rill_core.settlement import FundingBindingTransactionMatch, check_funding_binding_transaction
from rill_crypto import Context
from test_core_tx_bytes import _context

from rill_provider import core_tx_bytes as module
from rill_provider.core_tx_bytes import (
    CoreProtocolError,
    CoreTransactionReader,
    CoreUnavailableError,
)

if TYPE_CHECKING:
    from pathlib import Path
    from types import TracebackType

    from rill_core.settlement import TaprootKeyOperations
    from rill_core.wire.messages import ContractTerms, FundingBinding
    from rill_core.wire.types import NetworkIdentity

REAL_CLIENT = httpx.Client
TIP = "b" * 64
BLOCK = "a" * 64
ACQUISITION_REFUSAL = r"^Core funding inclusion acquisition unavailable$"
INPUT_REFUSAL = r"^Core funding inclusion input invalid$"


class Harness:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: PLR0915 - complete isolated transport/clock harness
        self.terms, self.binding, self.network = _context()
        script = bytes.fromhex(self.binding.contract_script_pubkey)
        self.raw = (
            b"\x02\x00\x00\x00\x01"
            + bytes.fromhex(self.binding.lineage_anchor_txid)[::-1]
            + self.binding.lineage_anchor_vout.to_bytes(4, "little")
            + b"\x00"
            + b"\xff" * 4
            + b"\x02"
            + (1000).to_bytes(8, "little")
            + b"\x16\x00\x14"
            + b"\x22" * 20
            + int(self.binding.contract_value_sat).to_bytes(8, "little")
            + bytes([len(script)])
            + script
            + b"\x00" * 4
        )
        txid = hashlib.sha256(hashlib.sha256(self.raw).digest()).digest()[::-1].hex()
        self.binding = self.binding.model_copy(update={"funding_txid": txid})
        self.info: dict[str, Any] = {
            "chain": "regtest",
            "blocks": 100,
            "bestblockhash": TIP,
            "initialblockdownload": False,
        }
        self.hashes = {0: self.network.genesis_hash, 98: BLOCK, 100: TIP, 101: "d" * 64}
        self.output: object = {
            "bestblock": TIP,
            "confirmations": 3,
            "coinbase": False,
            "scriptPubKey": {"hex": self.binding.contract_script_pubkey},
            "value": int(self.binding.contract_value_sat) / 100000000,
        }
        self.ending_output: object = self.output
        self.change_info_at = 0
        self.after_info: dict[str, Any] = {}
        self.change_hash_at = 0
        self.info_count = self.output_count = 0
        self.calls: list[dict[str, Any]] = []
        self.elapsed = self.wall = 0.0
        self.native_elapsed = 0.0
        self.cleanup_error = False
        self.native = Mock(
            return_value=FundingBindingTransactionMatch(
                txid,
                self.binding.contract_vout,
                self.binding.lineage_anchor_txid,
                self.binding.lineage_anchor_vout,
            )
        )
        self.keys: TaprootKeyOperations = Mock()
        self.cookie = tmp_path / "core.cookie"
        self.cookie.write_text("__cookie__:SECRET_CANARY")
        self.cookie.chmod(0o600)
        self.reader = CoreTransactionReader(
            port=18443, cookie_path=self.cookie, network=self.network, wallet="NEVER_USED"
        )
        self.raw_result: object = self.raw.hex()
        self.rpc_fault: str | None = None
        self.raw_error = False
        self.closed = False
        state = self

        def respond(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/"
            payload = json.loads(request.content)
            state.calls.append(payload)
            method = payload["method"]
            if method == "getblockchaininfo":
                state.info_count += 1
                result: object = (
                    state.info | state.after_info
                    if state.change_info_at and state.info_count >= state.change_info_at
                    else state.info
                )
            elif method == "getblockhash":
                result = state.hashes[payload["params"][0]]
                if (
                    state.change_hash_at
                    and state.info_count >= state.change_hash_at
                    and payload["params"] == [98]
                ):
                    result = "f" * 64
            elif method == "gettxout":
                assert payload["params"] == [
                    state.binding.funding_txid,
                    state.binding.contract_vout,
                    False,
                ]
                state.output_count += 1
                result = state.output if state.output_count == 1 else state.ending_output
            elif method == "getrawtransaction":
                assert payload["params"] == [state.binding.funding_txid, False, BLOCK]
                result = state.raw_result
            else:
                raise AssertionError("non-observation RPC attempted")
            if state.raw_error and method == "getrawtransaction":
                body = {
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "error": {"code": -5, "message": "SECRET_CANARY"},
                }
            else:
                body = {"jsonrpc": "2.0", "id": payload["id"], "result": result}
            if state.rpc_fault == "id":
                body["id"] = -1
            encoded = json.dumps(body).encode()
            if state.rpc_fault == "duplicate":
                encoded = b'{"id":999,' + encoded[1:]
            return httpx.Response(200, stream=httpx.ByteStream(encoded))

        class Client(REAL_CLIENT):
            def __init__(self, **kwargs: Any) -> None:  # noqa: ANN401 - actual strict client with only deterministic transport replaced
                super().__init__(transport=httpx.MockTransport(respond), **kwargs)

            def __exit__(
                self,
                exc_type: type[BaseException] | None = None,
                exc_value: BaseException | None = None,
                traceback: TracebackType | None = None,
            ) -> None:
                super().__exit__(exc_type, exc_value, traceback)
                state.closed = True
                state.wall += state.elapsed
                if state.cleanup_error:
                    raise RuntimeError("SECRET_CANARY")

        def native(*args: Any, **kwargs: Any) -> FundingBindingTransactionMatch:  # noqa: ANN401 - validation delegation unchanged
            result: FundingBindingTransactionMatch = state.native(*args, **kwargs)
            state.wall += state.native_elapsed
            return result

        monkeypatch.setattr(httpx, "Client", Client)
        monkeypatch.setattr(time, "time", lambda: 1000 + state.wall)
        monkeypatch.setattr(time, "monotonic", lambda: 100 + state.wall)
        monkeypatch.setattr(module, "check_funding_binding_transaction", native)

    def observe(self, **kwargs: Any) -> module.CoreHistoricalTransaction:  # noqa: ANN401 - explicit input-fault matrix
        return self.reader.observe_funding_inclusion(
            self.binding, self.terms, keys=self.keys, **kwargs
        )


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    return Harness(tmp_path, monkeypatch)


def test_index_free_coordinates_native_correspondence_and_two_consistent_utxo_samples(
    harness: Harness,
) -> None:
    result = harness.observe()
    assert result.raw_transaction == harness.raw
    assert result.txid == harness.binding.funding_txid
    assert (result.block_height, result.block_hash, result.minimum_sampled_confirmations) == (
        98,
        BLOCK,
        3,
    )
    assert (result.tip_before_height, result.tip_before_hash) == (100, TIP)
    assert (result.tip_after_height, result.tip_after_hash) == (100, TIP)
    assert result.configured_network == harness.network
    assert result.started_at == result.completed_at == 1000
    assert harness.closed
    assert harness.output_count == 2
    harness.native.assert_called_once_with(
        harness.raw, harness.binding, harness.terms, keys=harness.keys
    )
    assert [call["params"] for call in harness.calls if call["method"] == "getrawtransaction"] == [
        [harness.binding.funding_txid, False, BLOCK]
    ]


def test_second_utxo_sample_compares_validated_semantics_not_rpc_metadata(harness: Harness) -> None:
    assert isinstance(harness.output, dict)
    harness.ending_output = dict(harness.output, unused_metadata="different representation")
    assert harness.observe().block_height == 98


@pytest.mark.parametrize("boundary", [1, 2, 3, 4])
@pytest.mark.parametrize("challenge", ["matching", "missing", "wrong"])
def test_signet_challenge_on_each_inclusion_tip(
    harness: Harness, boundary: int, challenge: str
) -> None:
    network: NetworkIdentity = import_module("test_network_adapters")._network("signet")  # noqa: SLF001 - existing fixture, keep this test's typing scope local
    harness.network = network
    harness.terms = harness.terms.model_copy(update={"network_identity": network})
    harness.reader = CoreTransactionReader(port=18443, cookie_path=harness.cookie, network=network)
    harness.hashes[0] = network.genesis_hash
    harness.info.update(chain="signet", signet_challenge=network.signet_challenge)
    harness.change_info_at = boundary
    if challenge == "missing":
        harness.after_info = {"signet_challenge": None}
    elif challenge == "wrong":
        harness.after_info = {"signet_challenge": "51"}
    if challenge == "matching":
        assert harness.observe().configured_network == network
    else:
        with pytest.raises(CoreUnavailableError, match=ACQUISITION_REFUSAL):
            harness.observe()
        assert harness.info_count == boundary


@pytest.mark.parametrize("boundary", [1, 2])
@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "depth_zero",
        "depth_negative",
        "depth_bool",
        "depth_float",
        "depth_large",
        "depth_insufficient",
        "bestblock",
        "coinbase",
        "value",
        "script",
        "malformed",
        "conflicting_depth",
    ],
)
def test_utxo_unknown_or_inconsistent_never_yields_coordinates(
    harness: Harness, boundary: int, fault: str
) -> None:
    assert isinstance(harness.output, dict)
    output = dict(harness.output)
    if fault == "missing":
        broken: object = None
    elif fault == "malformed":
        broken = "SECRET_CANARY"
    else:
        if fault.startswith("depth_"):
            output["confirmations"] = {
                "depth_zero": 0,
                "depth_negative": -1,
                "depth_bool": True,
                "depth_float": 3.0,
                "depth_large": 101,
                "depth_insufficient": 1,
            }[fault]
        elif fault == "bestblock":
            output["bestblock"] = "f" * 64
        elif fault == "coinbase":
            output["coinbase"] = True
        elif fault == "value":
            output["value"] += 0.00000001
        elif fault == "script":
            output["scriptPubKey"] = {"hex": "5120" + "f" * 64}
        elif fault == "conflicting_depth":
            output["confirmations"] = 4
        broken = output
    if boundary == 1:
        harness.output = broken
        if fault == "conflicting_depth":
            harness.hashes[97] = BLOCK
    else:
        harness.ending_output = broken
    with pytest.raises(CoreUnavailableError, match=ACQUISITION_REFUSAL) as error:
        harness.observe()
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.parametrize("boundary", [1, 2, 3, 4])
@pytest.mark.parametrize("fault", ["advance", "fork", "ibd", "chain", "bool_height", "bad_hash"])
def test_every_sampled_tip_boundary_must_match(harness: Harness, boundary: int, fault: str) -> None:
    harness.change_info_at = boundary
    faults: dict[str, dict[str, Any]] = {
        "advance": {"blocks": 101, "bestblockhash": "d" * 64},
        "fork": {"bestblockhash": "f" * 64},
        "ibd": {"initialblockdownload": True},
        "chain": {"chain": "main"},
        "bool_height": {"blocks": True},
        "bad_hash": {"bestblockhash": "SECRET_CANARY"},
    }
    harness.after_info = faults[fault]
    with pytest.raises(CoreUnavailableError, match=ACQUISITION_REFUSAL):
        harness.observe()


@pytest.mark.parametrize(
    "fault",
    [
        "genesis",
        "canonical_tip",
        "inclusion_branch",
        "raw_bytes",
        "raw_txid",
        "native",
        "rpc_id",
        "rpc_duplicate",
        "unavailable",
        "cleanup_error",
        "cleanup_late",
        "native_late",
        "clock_backwards",
    ],
)
def test_acquisition_and_cleanup_faults_are_detached(harness: Harness, fault: str) -> None:  # noqa: PLR0912 - explicit distinct acquisition faults
    if fault == "genesis":
        harness.hashes[0] = "f" * 64
    elif fault == "canonical_tip":
        harness.hashes[100] = "f" * 64
    elif fault == "inclusion_branch":
        harness.change_hash_at = 3
    elif fault == "raw_bytes":
        harness.raw_result = "SECRET_CANARY"
    elif fault == "raw_txid":
        harness.raw_result = harness.raw[:-4].hex() + "01000000"
    elif fault == "native":
        harness.native.side_effect = ValueError("SECRET_CANARY")
    elif fault == "rpc_id":
        harness.rpc_fault = "id"
    elif fault == "rpc_duplicate":
        harness.rpc_fault = "duplicate"
    elif fault == "unavailable":
        harness.raw_error = True
    elif fault == "cleanup_error":
        harness.cleanup_error = True
    elif fault == "cleanup_late":
        harness.elapsed = 11
    elif fault == "native_late":
        harness.native_elapsed = 11
    elif fault == "clock_backwards":
        harness.elapsed = -1
    with pytest.raises(CoreUnavailableError, match=ACQUISITION_REFUSAL) as error:
        harness.observe()
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert all(
        call["method"] in {"getblockchaininfo", "getblockhash", "gettxout", "getrawtransaction"}
        for call in harness.calls
    )


@pytest.mark.parametrize("value", [True, 0, -1, 11, float("inf"), float("nan"), "SECRET_CANARY"])
def test_bad_budget_is_rejected_before_transport(harness: Harness, value: object) -> None:
    with pytest.raises(CoreProtocolError, match=INPUT_REFUSAL) as error:
        harness.observe(deadline_seconds=value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert harness.calls == []


@pytest.mark.parametrize(
    "fault", ["different_network", "unsupported_profile", "bypassed_binding", "bypassed_terms"]
)
def test_parsed_input_correspondence_and_support_before_cookie_access(
    harness: Harness, fault: str
) -> None:
    if fault == "different_network":
        harness.terms = harness.terms.model_copy(
            update={
                "network_identity": harness.network.model_copy(
                    update={"deployment_namespace": "other"}
                )
            }
        )
    elif fault == "unsupported_profile":
        harness.terms = harness.terms.model_copy(
            update={
                "network_identity": harness.network.model_copy(
                    update={"consensus_profile": "older-profile"}
                )
            }
        )
    elif fault == "bypassed_binding":
        harness.binding = harness.binding.model_copy(update={"contract_vout": True})
    elif fault == "bypassed_terms":
        harness.terms = harness.terms.model_copy(update={"funding_confirmations": True})
    harness.cookie.unlink()
    with pytest.raises(CoreProtocolError, match=INPUT_REFUSAL) as error:
        harness.observe()
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert harness.calls == []


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="explicit native funding correspondence opt-in",
)
@pytest.mark.parametrize("fault", [False, True])
def test_actual_native_known_binding_output_and_anchor(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, *, fault: bool
) -> None:
    monkeypatch.setattr(
        module, "check_funding_binding_transaction", check_funding_binding_transaction
    )
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as keys:
        harness.keys = keys
        if fault:
            harness.binding = harness.binding.model_copy(update={"lineage_anchor_txid": "ff" * 32})
            with pytest.raises(CoreUnavailableError, match=ACQUISITION_REFUSAL):
                harness.observe()
        else:
            assert harness.observe().raw_transaction == harness.raw


@pytest.mark.parametrize("target", ["binding", "terms"])
def test_bypassed_serializer_warnings_cannot_emit_private_input_before_detachment(
    harness: Harness, target: str
) -> None:
    canary = {"SECRET_CANARY": True}
    model: FundingBinding | ContractTerms
    if target == "binding":
        harness.binding = harness.binding.model_copy(update={"funding_attempt_id": canary})
        model = harness.binding
    else:
        harness.terms = harness.terms.model_copy(update={"required_features": canary})
        model = harness.terms
    # Affirmatively characterize the installed serializer's default diagnostic
    # without leaking it to stderr. The public method must turn it into an error.
    with warnings.catch_warnings(record=True) as baseline:
        warnings.simplefilter("always")
        model.model_dump_json()
    assert any("SECRET_CANARY" in str(warning.message) for warning in baseline)
    harness.cookie.unlink()
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        with pytest.raises(CoreProtocolError, match=INPUT_REFUSAL) as error:
            harness.observe()
    assert emitted == []
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert harness.calls == []
