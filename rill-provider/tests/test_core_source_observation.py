"""Protected local HTTP RPC observation, never source-custody authority."""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from rill_core.networks import DEFAULT_SIGNET_CHALLENGE, PUBLIC_CONSENSUS_PROFILE
from rill_core.wire.types import NetworkIdentity
from test_core_tx_bytes import GENESIS, _context, _cookie, _server

from rill_provider import core_tx_bytes as module

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def reply(
    fault: str = "none", clock: list[float] | None = None
) -> Callable[[dict[str, Any]], tuple[int, bytes]]:
    def response(payload: dict[str, Any]) -> tuple[int, bytes]:
        method, identifier = payload["method"], payload["id"]
        if method == "getblockchaininfo":
            value: Any = {
                "chain": "regtest",
                "blocks": 105,
                "bestblockhash": "a" * 64,
                "initialblockdownload": False,
            }
            if fault == "chain":
                value["chain"] = "main"
            elif fault == "ibd":
                value["initialblockdownload"] = True
            elif fault == "tip_height":
                value["blocks"] = True
            elif fault == "tip_hash":
                value["bestblockhash"] = "SECRET_CANARY"
            elif fault == "tip_change" and identifier == 4:
                value["blocks"] = 106
        else:
            value = GENESIS if payload["params"] == [0] else "c" * 64
            if fault == "genesis" and identifier == 2:
                value = "b" * 64
            elif fault == "source_hash" and identifier == 3:
                value = "SECRET_CANARY"
            elif fault == "active_change" and identifier == 5:
                value = "d" * 64
        if clock is not None and identifier == 3:
            clock[0] += 11
        envelope = {"jsonrpc": "2.0", "id": identifier, "result": value}
        if fault == "envelope":
            envelope["id"] = True
        return 200, json.dumps(envelope).encode()

    return response


def refused(action: Callable[[], object]) -> None:
    with pytest.raises(module.CoreReadError) as failure:
        action()
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert "SECRET_CANARY" not in str(failure.value)


def test_readonly_source_snapshot_separates_config_from_authenticated_claims(
    tmp_path: Path,
) -> None:
    _terms, _binding, network = _context()
    requests: list[dict[str, Any]] = []
    with _server(reply(), requests) as port:
        reader = module.CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network
        )
        assert not requests
        result = reader.observe_source(103)
    assert result.configured_network == network
    assert result.observed_chain == "regtest"
    assert result.genesis_hash == GENESIS
    assert result.signet_challenge is None
    assert (result.tip_height, result.tip_hash) == (105, "a" * 64)
    assert (result.source_height, result.source_block_hash) == (103, "c" * 64)
    assert [(call["method"], call["params"]) for call in requests] == [
        ("getblockchaininfo", []),
        ("getblockhash", [0]),
        ("getblockhash", [103]),
        ("getblockchaininfo", []),
        ("getblockhash", [103]),
    ]
    assert all(call["path"] == "/" and call["auth"].startswith("Basic ") for call in requests)
    assert "secret" not in str(asdict(result))
    assert not hasattr(result, "spendable_msat")


@pytest.mark.parametrize(
    "fault",
    [
        "chain",
        "ibd",
        "tip_height",
        "tip_hash",
        "tip_change",
        "genesis",
        "source_hash",
        "active_change",
        "envelope",
    ],
)
def test_inconsistent_source_is_unknown_not_absence_or_inventory_zero(
    tmp_path: Path, fault: str
) -> None:
    _terms, _binding, network = _context()
    requests: list[dict[str, Any]] = []
    with _server(reply(fault), requests) as port:
        reader = module.CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network
        )
        refused(lambda: reader.observe_source(103))


@pytest.mark.parametrize("height", [True, 0, -1, "103", 106, 105])
def test_invalid_height_or_tip_hash_disagreement_refuses(tmp_path: Path, height: Any) -> None:  # noqa: ANN401 - malformed caller matrix
    _terms, _binding, network = _context()
    requests: list[dict[str, Any]] = []
    with _server(reply(), requests) as port:
        reader = module.CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network
        )
        refused(lambda: reader.observe_source(height))
    if type(height) is not int or height <= 0:
        assert not requests


@pytest.mark.parametrize("duration", [True, 0, -1, 11, 10**400, float("nan"), float("inf")])
def test_invalid_source_duration_is_inert(tmp_path: Path, duration: float) -> None:
    _terms, _binding, network = _context()
    reader = module.CoreTransactionReader(port=1, cookie_path=tmp_path / "missing", network=network)
    refused(lambda: reader.observe_source(103, deadline_seconds=duration))


@pytest.mark.parametrize("phase", ["cookie", "rpc", "cleanup"])
def test_source_acceptance_budget_includes_cookie_rpc_and_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    _terms, _binding, network = _context()
    clock = [100.0]
    requests: list[dict[str, Any]] = []
    with _server(reply(clock=clock if phase == "rpc" else None), requests) as port:
        reader = module.CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network
        )
        monkeypatch.setattr(time, "monotonic", lambda: clock[0])
        if phase == "cookie":
            cookie = module._cookie  # noqa: SLF001 - full setup acceptance budget

            def delayed_cookie(path: Path) -> tuple[str, str]:
                result = cookie(path)
                clock[0] += 11
                return result

            monkeypatch.setattr(module, "_cookie", delayed_cookie)
        elif phase == "cleanup":
            close = httpx.Client.__exit__

            def delayed_close(client: httpx.Client, *args: Any) -> None:  # noqa: ANN401 - httpx context exit instrumentation
                close(client, *args)
                clock[0] += 11

            monkeypatch.setattr(httpx.Client, "__exit__", delayed_close)
        refused(lambda: reader.observe_source(103))
    if phase == "cookie":
        assert not requests


def test_source_rpc_uses_remaining_budget_not_existing_fixed_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _terms, _binding, network = _context()
    timeouts: list[float] = []
    stream = httpx.Client.stream

    def timed(client: httpx.Client, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401 - preserve httpx signature in instrumentation
        timeout = kwargs["timeout"]
        assert isinstance(timeout, httpx.Timeout)
        assert timeout.read is not None
        timeouts.append(timeout.read)
        return stream(client, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "stream", timed)
    with _server(reply(), []) as port:
        reader = module.CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network
        )
        reader.observe_source(103, deadline_seconds=2)
    assert len(timeouts) == 5
    assert all(0 < value <= 2 for value in timeouts)
    assert timeouts == sorted(timeouts, reverse=True)


@pytest.mark.parametrize("challenge", [DEFAULT_SIGNET_CHALLENGE, "51", None])
def test_signet_checks_observed_challenge_not_only_configured_label(
    tmp_path: Path, challenge: str | None
) -> None:
    network = NetworkIdentity(
        family="bitcoin",
        name="signet",
        genesis_hash="00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
        signet_challenge=DEFAULT_SIGNET_CHALLENGE,
        consensus_profile=PUBLIC_CONSENSUS_PROFILE,
        deployment_namespace=None,
    )
    normal = reply()

    def signed(payload: dict[str, Any]) -> tuple[int, bytes]:
        status, document = normal(payload)
        envelope = json.loads(document)
        if payload["method"] == "getblockchaininfo":
            envelope["result"]["chain"] = "signet"
            envelope["result"]["signet_challenge"] = challenge
        elif payload["params"] == [0]:
            envelope["result"] = network.genesis_hash
        return status, json.dumps(envelope).encode()

    with _server(signed, []) as port:
        reader = module.CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network
        )
        if challenge == DEFAULT_SIGNET_CHALLENGE:
            observed = reader.observe_source(103)
            assert observed.signet_challenge == DEFAULT_SIGNET_CHALLENGE
            assert observed.observed_chain == "signet"
        else:
            refused(lambda: reader.observe_source(103))


@pytest.mark.parametrize("phase", ["stream", "cleanup"])
def test_private_http_or_cleanup_exceptions_are_detached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    _terms, _binding, network = _context()
    if phase == "stream":

        def bad_stream(_client: httpx.Client, *_args: Any, **_kwargs: Any) -> Any:  # noqa: ANN401 - simulated upstream error
            raise httpx.HTTPError("SECRET_CANARY")

        monkeypatch.setattr(httpx.Client, "stream", bad_stream)
    else:
        close = httpx.Client.__exit__

        def bad_close(client: httpx.Client, *args: Any) -> None:  # noqa: ANN401 - simulated cleanup error
            close(client, *args)
            raise RuntimeError("SECRET_CANARY")

        monkeypatch.setattr(httpx.Client, "__exit__", bad_close)
    with _server(reply(), []) as port:
        reader = module.CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network
        )
        refused(lambda: reader.observe_source(103))
