"""Explicit regtest send is once-only and never conflates RPC with confirmation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Self

import pytest
from rill_core.wire.messages import ContractTerms, FundingBinding

from rill_cli import refund_broadcast as broadcast
from rill_cli.recovery_core_observation import RecoveryOutpointCandidate

if TYPE_CHECKING:
    from rill_core.wire.types import NetworkIdentity

FIXTURE = Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json"


def _fixture() -> tuple[ContractTerms, FundingBinding, NetworkIdentity, RecoveryOutpointCandidate]:
    source = json.loads(FIXTURE.read_bytes())
    terms = ContractTerms.model_validate_json(json.dumps(source["contract_terms"]))
    binding = FundingBinding.model_validate(
        {
            "contract_hash": source["contract_hash"],
            "funding_attempt_id": "cc" * 32,
            "binding_revision": 0,
            "funder_role": "client",
            "lineage_anchor_txid": "dd" * 32,
            "lineage_anchor_vout": 1,
            "funding_txid": "aa" * 32,
            "contract_vout": 0,
            "contract_value_sat": terms.economics.contract_amount_sat,
            "contract_script_pubkey": source["taproot_contract"]["script_pubkey"],
            "replaces_txid": None,
            "created_at": 1700000200,
        }
    )
    from rill_core.settlement import FundingBindingTransactionMatch  # noqa: PLC0415

    candidate = RecoveryOutpointCandidate(
        terms.network_identity,
        FundingBindingTransactionMatch(
            binding.funding_txid,
            binding.contract_vout,
            binding.lineage_anchor_txid,
            binding.lineage_anchor_vout,
        ),
        "ab" * 32,
        1101,
        "bc" * 32,
        1100,
        2,
        1101,
    )
    return terms, binding, terms.network_identity, candidate


def test_exact_refund_intent_is_canonical_and_detects_readback_changes() -> None:
    terms, binding, _, candidate = _fixture()
    raw = b"\x02\x00\x00\x00test-only signed bytes"
    intent = broadcast.create_refund_intent(
        raw,
        txid="11" * 32,
        binding=binding,
        terms=terms,
        fee_sat=300,
        candidate=candidate,
    )
    assert broadcast.verify_refund_intent(intent, intent) == raw
    parsed = json.loads(intent)
    assert parsed["kind"] == "regtest-refund-submission-intent/v1"
    assert parsed["state"] == "submission_may_occur"
    assert parsed["refund_txid"] == "11" * 32
    assert parsed["funding_attempt_id"] == binding.funding_attempt_id
    assert parsed["binding_revision"] == 0
    for changed in (b" " + intent, intent[:-1], intent.replace(b"300", b"301", 1)):
        with pytest.raises(broadcast.RefundPreflightError):
            broadcast.verify_refund_intent(changed, intent)
    with pytest.raises(broadcast.RefundPreflightError):
        broadcast.create_refund_intent(
            raw,
            txid="11" * 32,
            binding=binding,
            terms=terms,
            fee_sat=300,
            candidate=candidate.__class__(
                candidate.network_identity,
                candidate.static_match,
                candidate.tip_hash,
                1100,
                candidate.transaction_lookup_block_hash,
                candidate.sampled_inclusion_height,
                candidate.chain_only_confirmations,
                candidate.refund_first_eligible_height,
            ),
        )


@pytest.mark.parametrize(
    "mode",
    [
        "accepted",
        "observe-unavailable",
        "preflight-denied",
        "preflight-malformed",
        "preflight-transport",
        "send-timeout",
        "wrong-txid",
    ],
)
def test_submit_once_only_after_fresh_observation_and_exact_preflight(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    terms, binding, _, candidate = _fixture()
    observed: list[str] = []
    raw = b"\x02\x00\x00\x00test-only signed bytes"
    txid = "11" * 32

    class Reader:
        _cookie_path = Path("/never-read")
        _url = "http://127.0.0.1:18443/"

        def observe(
            self, selected: FundingBinding, _terms: ContractTerms, *, keys: object, for_refund: bool
        ) -> RecoveryOutpointCandidate:
            assert selected == binding
            assert keys is not None
            assert for_refund is True
            observed.append("observe")
            if mode == "observe-unavailable":
                raise TimeoutError("private stale chain evidence")
            return candidate

        def _rpc(
            self, _client: object, method: str, params: list[object], _id: int, *, submission: bool
        ) -> object:
            assert submission is True
            assert params == ([[raw.hex()]] if method == "testmempoolaccept" else [raw.hex()])
            observed.append(method)
            if method == "testmempoolaccept":
                if mode == "preflight-transport":
                    raise TimeoutError("private preflight request")
                if mode == "preflight-malformed":
                    return [{"allowed": 1, "txid": txid}]
                return [{"allowed": mode != "preflight-denied", "txid": txid}]
            if mode == "send-timeout":
                raise TimeoutError("private send request with cookie")
            return "22" * 32 if mode == "wrong-txid" else txid

    class Client:
        def __init__(self, **_kwargs: object) -> None:
            observed.append("client")

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(broadcast, "_cookie", lambda _path: ("__cookie__", "private"))
    monkeypatch.setattr(broadcast.httpx, "Client", Client)
    reader = Reader()
    if mode == "accepted":
        assert (
            broadcast.submit_prepared_refund(
                reader,
                binding,
                terms,
                keys=object(),
                raw=raw,
                expected_txid=txid,  # type: ignore[arg-type]
            )
            == candidate
        )
    else:
        category = (
            broadcast.RefundSubmissionUnknownError
            if mode in {"send-timeout", "wrong-txid"}
            else broadcast.RefundPreflightError
        )
        with pytest.raises(category) as error:
            broadcast.submit_prepared_refund(
                reader,
                binding,
                terms,
                keys=object(),
                raw=raw,
                expected_txid=txid,  # type: ignore[arg-type]
            )
        assert error.value.__context__ is None
        assert error.value.__cause__ is None
        assert "private" not in repr(error.value)
    assert observed[:3] == (
        ["observe"] if mode == "observe-unavailable" else ["observe", "client", "testmempoolaccept"]
    )
    assert observed.count("sendrawtransaction") == (
        1 if mode in {"accepted", "send-timeout", "wrong-txid"} else 0
    )
