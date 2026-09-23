"""Read-only selected-chain candidate sampling, never a spend decision."""

from __future__ import annotations

import base64
import json
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from rill_core.wire.messages import ContractTerms, FundingBinding

from rill_cli import recovery_core_observation as observation

if TYPE_CHECKING:
    from rill_core.wire.types import NetworkIdentity

FIXTURE = Path(__file__).parent / "fixtures" / "initial-btc-to-ln-v1.json"


def _context() -> tuple[ContractTerms, FundingBinding, NetworkIdentity]:
    package = json.loads(FIXTURE.read_text())
    terms = ContractTerms.model_validate_json(json.dumps(package["contract_terms"]))
    binding = FundingBinding.model_validate_json(
        json.dumps(
            {
                "contract_hash": package["contract_hash"],
                "funding_attempt_id": "cc" * 32,
                "binding_revision": 0,
                "funder_role": "client",
                "lineage_anchor_txid": "dd" * 32,
                "lineage_anchor_vout": 1,
                "funding_txid": "aa" * 32,
                "contract_vout": 0,
                "contract_value_sat": terms.economics.contract_amount_sat,
                "contract_script_pubkey": package["taproot_contract"]["script_pubkey"],
                "replaces_txid": None,
                "created_at": 1700000200,
            }
        )
    )
    return terms, binding, terms.network_identity


def _cookie(tmp_path: Path) -> Path:
    path = tmp_path / "cookie"
    path.write_text("__cookie__:private-test-password")
    path.chmod(0o600)
    return path


def _replies(
    requests: list[dict[str, Any]],
    binding: FundingBinding,
    network: NetworkIdentity,
    *,
    change: str = "none",
) -> httpx.MockTransport:
    tip = "11" * 32
    inclusion = tip if change == "at-tip" else "22" * 32

    def handle(request: httpx.Request) -> httpx.Response:  # noqa: PLR0911, PLR0912 - adversarial RPC replies
        assert request.method == "POST"
        assert request.url.path == "/"
        assert request.headers.get("Accept-Encoding") == "identity"
        assert request.headers.get("Authorization", "").startswith("Basic ")
        assert base64.b64decode(request.headers["Authorization"].split(" ", 1)[1]) == (
            b"__cookie__:private-test-password"
        )
        payload = json.loads(request.content)
        requests.append(payload)
        method = payload["method"]
        identifier = payload["id"]
        if change == "unauthorized":
            return httpx.Response(401, text="private upstream auth text")
        if change == "transport-error":
            raise httpx.ReadError("private-request", request=request)
        if change == "oversize":
            return httpx.Response(200, content=b"x" * (observation.MAX_RESPONSE_BYTES + 1))
        if change == "compressed":
            return httpx.Response(
                200, headers={"Content-Encoding": "gzip"}, stream=httpx.ByteStream(b"invalid")
            )
        info = {
            "chain": "regtest",
            "blocks": 100,
            "bestblockhash": tip,
            "initialblockdownload": False,
        }
        if change == "tip-changed" and identifier == 6:
            info["bestblockhash"] = "33" * 32
        result: object = {
            "getblockchaininfo": info,
            "getblockhash": (
                network.genesis_hash
                if payload["params"] == [0]
                else "ff" * 32
                if change == "aba" and identifier == 4
                else inclusion
            ),
            "gettxout": {
                "bestblock": tip,
                "confirmations": 1 if change in {"at-tip", "block"} else 2,
                "coinbase": False,
                "value": Decimal(binding.contract_value_sat) / Decimal(100_000_000),
                "scriptPubKey": {"hex": binding.contract_script_pubkey},
            },
            "getrawtransaction": "02000000000100",
        }[method]
        if change == "null" and method == "gettxout":
            result = None
        if change == "amount" and method == "gettxout":
            result["value"] = Decimal("0.00101001")  # type: ignore[index]
        if change == "script" and method == "gettxout":
            result["scriptPubKey"] = {"hex": "5120" + "ee" * 32}  # type: ignore[index]
        if change == "genesis" and identifier == 2:
            result = "ff" * 32
        if change == "block" and identifier == 4:
            result = "ff" * 32
        if change == "missing-tx" and method == "getrawtransaction":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": identifier,
                    "error": {"code": -5, "message": "private upstream text"},
                },
            )
        if change == "duplicate-json" and identifier == 1:
            return httpx.Response(200, content=b'{"jsonrpc":"2.0","id":1,"result":{},"result":{}}')
        if change == "wrong-id" and identifier == 1:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 9, "result": info})
        return httpx.Response(
            200,
            content=json.dumps(
                {"jsonrpc": "2.0", "id": identifier, "result": result},
                default=lambda value: float(value) if isinstance(value, Decimal) else value,
            ).encode(),
        )

    def streamed(request: httpx.Request) -> httpx.Response:
        response = handle(request)
        if change == "compressed":
            return response
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=httpx.ByteStream(response.content),
        )

    return httpx.MockTransport(streamed)


def _reader(  # noqa: PLR0913 - test seam controls independent inputs
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    binding: FundingBinding,
    network: NetworkIdentity,
    requests: list[dict[str, Any]],
    *,
    change: str = "none",
) -> observation.RegtestRecoveryCoreReader:
    client = httpx.Client

    def make_client(**kwargs: object) -> httpx.Client:
        return client(transport=_replies(requests, binding, network, change=change), **kwargs)

    monkeypatch.setattr(observation.httpx, "Client", make_client)
    return observation.RegtestRecoveryCoreReader(
        port=18443, cookie_path=_cookie(tmp_path), network=network
    )


@pytest.mark.parametrize("change", ["none", "at-tip"])
def test_selected_candidate_uses_block_qualified_bytes_without_txindex(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    terms, binding, network = _context()
    requests: list[dict[str, Any]] = []
    reader = _reader(tmp_path, monkeypatch, binding, network, requests, change=change)
    matched = object()
    checked: list[bytes] = []

    def match(raw: bytes, *_args: object, **_kwargs: object) -> object:
        checked.append(raw)
        return matched

    monkeypatch.setattr(observation, "check_funding_binding_transaction", match)
    candidate = reader.observe(binding, terms, keys=object())  # type: ignore[arg-type]
    assert candidate.static_match is matched
    assert checked == [bytes.fromhex("02000000000100")]
    assert candidate.chain_only_confirmations == (1 if change == "at-tip" else 2)
    assert candidate.sampled_inclusion_height == (100 if change == "at-tip" else 99)
    assert candidate.refund_first_eligible_height == terms.refund_lock_height + 1
    assert [request["method"] for request in requests] == [
        "getblockchaininfo",
        "getblockhash",
        "gettxout",
        "getblockhash",
        "getrawtransaction",
        "getblockchaininfo",
        "getblockhash",
    ]
    assert requests[2]["params"] == [binding.funding_txid, binding.contract_vout, False]
    assert requests[4]["params"] == [
        binding.funding_txid,
        False,
        candidate.transaction_lookup_block_hash,
    ]
    assert requests[6]["params"] == [candidate.sampled_inclusion_height]


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ("null", observation.RecoveryCoreUnavailableError),
        ("amount", observation.RecoveryCoreProtocolError),
        ("script", observation.RecoveryCoreProtocolError),
        ("genesis", observation.RecoveryCoreProtocolError),
        ("block", observation.RecoveryCoreProtocolError),
        ("tip-changed", observation.RecoveryCoreUnavailableError),
        ("aba", observation.RecoveryCoreUnavailableError),
        ("transport-error", observation.RecoveryCoreUnavailableError),
        ("missing-tx", observation.RecoveryCoreUnavailableError),
        ("duplicate-json", observation.RecoveryCoreProtocolError),
        ("oversize", observation.RecoveryCoreProtocolError),
        ("compressed", observation.RecoveryCoreProtocolError),
        ("wrong-id", observation.RecoveryCoreProtocolError),
        ("unauthorized", observation.RecoveryCoreUnavailableError),
    ],
)
def test_invalid_or_missing_core_evidence_is_never_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
    error: type[Exception],
) -> None:
    terms, binding, network = _context()
    requests: list[dict[str, Any]] = []
    reader = _reader(tmp_path, monkeypatch, binding, network, requests, change=change)
    monkeypatch.setattr(
        observation, "check_funding_binding_transaction", lambda *_a, **_k: object()
    )
    with pytest.raises(error) as caught:
        reader.observe(binding, terms, keys=object())  # type: ignore[arg-type]
    assert "private upstream" not in repr(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_native_match_failure_does_not_retain_secret_exception_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terms, binding, network = _context()
    reader = _reader(tmp_path, monkeypatch, binding, network, [])

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("private-key material")

    monkeypatch.setattr(observation, "check_funding_binding_transaction", fail)
    with pytest.raises(observation.RecoveryCoreProtocolError) as error:
        reader.observe(binding, terms, keys=object())  # type: ignore[arg-type]
    assert "private-key" not in repr(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_cookie_and_loopback_preflight_fail_before_rpc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terms, binding, network = _context()
    requests: list[dict[str, Any]] = []
    reader = _reader(tmp_path, monkeypatch, binding, network, requests)
    reader._cookie_path.chmod(0o644)  # noqa: SLF001 - explicit private cookie boundary
    with pytest.raises(observation.RecoveryCoreUnavailableError):
        reader.observe(binding, terms, keys=object())  # type: ignore[arg-type]
    assert requests == []
    with pytest.raises(ValueError, match="loopback"):
        observation.RegtestRecoveryCoreReader(
            port=18443, cookie_path=tmp_path / "cookie", network=network, host="192.0.2.1"
        )
    with pytest.raises(ValueError, match="loopback"):
        observation.RegtestRecoveryCoreReader(
            port=True, cookie_path=tmp_path / "cookie", network=network
        )  # type: ignore[arg-type]
    assert requests == []
