"""Own-Core witness requests are authorized at HTTP transport handoff."""

from __future__ import annotations

import json
from unittest.mock import Mock

import httpx
import pytest
from test_wallet_rpc import answers as answers  # noqa: PLC0414 - reuse existing Core server fixture
from test_wallet_rpc import core as core  # noqa: PLC0414 - reuse existing Core server fixture

from rill_cli import wallet_rpc
from rill_cli.wallet_rpc import WalletRpcError

TXID = "aa" * 32


@pytest.mark.parametrize(
    "boundary", ["attestation", "cookie", "client setup", "request setup", "auth setup"]
)
@pytest.mark.parametrize("reason", ["expired", "revoked"])
def test_guard_refuses_delayed_broadcast_before_transport_handoff(  # noqa: PLR0915 - each real boundary has a distinct delay injection
    core: tuple,
    answers: dict,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    reason: str,
) -> None:
    wallet, calls = core
    answers["sendrawtransaction"] = TXID
    clock, permission = {"now": 100.0}, {"allowed": True}
    monkeypatch.setattr(wallet_rpc, "time", Mock(monotonic=lambda: clock["now"]))

    def revoke() -> None:
        if reason == "expired":
            clock["now"] = 110.0
        else:
            permission["allowed"] = False

    if boundary == "attestation":
        original = wallet._verify_network  # noqa: SLF001 - real attestation still runs

        def verify(**kwargs: object) -> int:
            height = original(**kwargs)
            revoke()
            return height

        monkeypatch.setattr(wallet, "_verify_network", verify)
    elif boundary == "cookie":
        cookie = wallet_rpc._cookie  # noqa: SLF001 - actual credential read ordering
        read = 0

        def credentials(path: object) -> tuple:
            nonlocal read
            result = cookie(path)
            read += 1
            if read == 3:
                revoke()
            return result

        monkeypatch.setattr(wallet_rpc, "_cookie", credentials)
    elif boundary == "client setup":
        original_client = httpx.Client
        built = 0

        def client(**kwargs: object) -> httpx.Client:
            nonlocal built
            result = original_client(**kwargs)
            built += 1
            if built == 3:
                revoke()
            return result

        monkeypatch.setattr(httpx, "Client", client)
    elif boundary == "request setup":
        build_request = httpx.Client.build_request

        def build(self: httpx.Client, *args: object, **kwargs: object) -> httpx.Request:
            request = build_request(self, *args, **kwargs)
            if json.loads(request.content)["method"] == "sendrawtransaction":
                revoke()
            return request

        monkeypatch.setattr(httpx.Client, "build_request", build)
    else:
        auth_flow = httpx.BasicAuth.auth_flow

        def auth(self: httpx.BasicAuth, request: httpx.Request) -> object:
            if json.loads(request.content)["method"] == "sendrawtransaction":
                revoke()
            yield from auth_flow(self, request)

        monkeypatch.setattr(httpx.BasicAuth, "auth_flow", auth)

    with pytest.raises(WalletRpcError, match="authority"):
        wallet.broadcast(
            b"witness-bearing bytes", deadline=110.0, effect_allowed=lambda: permission["allowed"]
        )
    assert [call["method"] for call in calls] == ["getblockchaininfo", "getblockhash"]


def test_final_permission_delay_is_followed_by_a_fresh_deadline_sample(
    core: tuple,
    answers: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wallet, calls = core
    answers["sendrawtransaction"] = TXID
    clock = {"now": 100.0}
    ready = False
    monkeypatch.setattr(wallet_rpc, "time", Mock(monotonic=lambda: clock["now"]))
    original = httpx.Client.build_request

    def build(self: httpx.Client, *args: object, **kwargs: object) -> httpx.Request:
        nonlocal ready
        request = original(self, *args, **kwargs)
        ready = json.loads(request.content)["method"] == "sendrawtransaction"
        return request

    monkeypatch.setattr(httpx.Client, "build_request", build)

    def allowed() -> bool:
        if ready:
            clock["now"] = 110.0
        return True

    with pytest.raises(WalletRpcError, match="expired"):
        wallet.broadcast(b"witness", deadline=110.0, effect_allowed=allowed)
    assert all(call["method"] != "sendrawtransaction" for call in calls)


@pytest.mark.parametrize("budget", [1.0, 100.0])
def test_authorized_handoff_preserves_request_and_refreshes_all_phase_timeouts(
    core: tuple,
    answers: dict,
    monkeypatch: pytest.MonkeyPatch,
    budget: float,
) -> None:
    wallet, calls = core
    answers["sendrawtransaction"] = TXID
    monkeypatch.setattr(wallet_rpc, "time", Mock(monotonic=lambda: 100.0))
    original = httpx.Client
    requests: list[httpx.Request] = []

    def client(**kwargs: object) -> httpx.Client:
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        kwargs["event_hooks"]["request"].append(requests.append)
        return original(**kwargs)

    monkeypatch.setattr(httpx, "Client", client)
    raw = b"exact witness-bearing transaction"
    assert wallet.broadcast(raw, deadline=100.0 + budget, effect_allowed=lambda: True) == TXID
    assert [call["method"] for call in calls] == [
        "getblockchaininfo",
        "getblockhash",
        "sendrawtransaction",
    ]
    assert calls[-1]["path"] == "/"
    assert calls[-1]["params"] == [raw.hex()]
    assert all(request.headers["authorization"].startswith("Basic ") for request in requests)
    assert all(
        request.extensions["timeout"]
        == {
            "connect": min(2.0, budget),
            "read": min(30.0, budget),
            "write": min(30.0, budget),
            "pool": min(30.0, budget),
        }
        for request in requests
    )


@pytest.mark.parametrize("outcome", ["late success", "ambiguous failure"])
def test_post_handoff_outcomes_do_not_trigger_retry_or_prove_privacy(
    core: tuple,
    answers: dict,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
) -> None:
    wallet, calls = core
    answers["sendrawtransaction"] = TXID
    clock = {"now": 100.0}
    monkeypatch.setattr(wallet_rpc, "time", Mock(monotonic=lambda: clock["now"]))
    original_send = httpx.Client.send

    def send(self: httpx.Client, request: httpx.Request, **kwargs: object) -> httpx.Response:
        response = original_send(self, request, **kwargs)
        if json.loads(request.content)["method"] == "sendrawtransaction":
            clock["now"] = 200.0
            if outcome == "ambiguous failure":
                raise httpx.ReadTimeout("sensitive network data")
        return response

    monkeypatch.setattr(httpx.Client, "send", send)
    if outcome == "late success":
        assert wallet.broadcast(b"witness", deadline=110.0) == TXID
    else:
        with pytest.raises(WalletRpcError, match="Core RPC unavailable") as error:
            wallet.broadcast(b"witness", deadline=110.0)
        assert "sensitive network data" not in str(error.value)
    assert sum(call["method"] == "sendrawtransaction" for call in calls) == 1


def test_successful_request_setup_refreshes_timeout_to_the_reduced_remainder(
    core: tuple,
    answers: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wallet, calls = core
    answers["sendrawtransaction"] = TXID
    clock = {"now": 100.0}
    monkeypatch.setattr(wallet_rpc, "time", Mock(monotonic=lambda: clock["now"]))
    client_class = httpx.Client
    original_build = client_class.build_request
    timeouts: dict[str, dict] = {}

    def build(self: httpx.Client, *args: object, **kwargs: object) -> httpx.Request:
        request = original_build(self, *args, **kwargs)
        if json.loads(request.content)["method"] == "sendrawtransaction":
            clock["now"] = 106.0
        return request

    def observe(request: httpx.Request) -> None:
        timeouts[json.loads(request.content)["method"]] = dict(request.extensions["timeout"])

    def client(**kwargs: object) -> httpx.Client:
        kwargs["event_hooks"]["request"].append(observe)
        return client_class(**kwargs)

    monkeypatch.setattr(client_class, "build_request", build)
    monkeypatch.setattr(httpx, "Client", client)
    assert wallet.broadcast(b"exact witness", deadline=110.0) == TXID
    assert [call["method"] for call in calls] == [
        "getblockchaininfo",
        "getblockhash",
        "sendrawtransaction",
    ]
    assert timeouts["getblockchaininfo"]["read"] == 10.0
    assert timeouts["getblockhash"]["read"] == 10.0
    assert timeouts["sendrawtransaction"] == {
        "connect": 2.0,
        "read": 4.0,
        "write": 4.0,
        "pool": 4.0,
    }


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), True, "110", 100.0])
def test_invalid_authority_performs_no_rpc(
    core: tuple, monkeypatch: pytest.MonkeyPatch, deadline: object
) -> None:
    wallet, calls = core
    monkeypatch.setattr(wallet_rpc, "time", Mock(monotonic=lambda: 100.0))
    with pytest.raises(WalletRpcError, match="authority"):
        wallet.broadcast(b"witness", deadline=deadline)
    assert calls == []


@pytest.mark.parametrize("answer", [False, None, 1, "raises"])
def test_permission_requires_positive_boolean_and_redacts_errors(
    core: tuple,
    answer: object,
) -> None:
    wallet, calls = core
    allowed = Mock(return_value=answer)
    if answer == "raises":
        allowed.side_effect = RuntimeError("sensitive permission data")
    with pytest.raises(WalletRpcError, match="authority unavailable") as error:
        wallet.broadcast(b"witness", effect_allowed=allowed)
    assert "sensitive permission data" not in str(error.value)
    assert calls == []
