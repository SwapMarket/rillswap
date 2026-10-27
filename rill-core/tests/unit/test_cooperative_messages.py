"""Structural safety for cooperative v1 action payloads, not signing authority."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from rill_core.wire.canonical import canonicalize
from rill_core.wire.cooperative_messages import (
    CooperativeClaimComplete,
    CooperativeClaimDeclined,
    CooperativeClaimPropose,
    CooperativeClaimReady,
    CooperativeClaimReadyRequest,
    CooperativeClaimSigned,
    CooperativeClaimVerified,
    check_cooperative_action_context,
    parse_cooperative_payload,
)
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    contract_hash,
    handshake_init_hash,
)
from rill_core.wire.messages import ContractTerms, Envelope, HandshakeAccept, HandshakeInit

ID = "01" * 32
NONCE = "02" * 66
PARTIAL = "03" * 32
FIXTURES = Path(__file__).parents[1] / "fixtures" / "recovery-v1"
SHARED_CYCLE = json.loads(
    (Path(__file__).parents[3] / "rill-docs/vectors/wire/cooperative-claim-v1.json").read_text()
)
PROPOSE = {
    "action": "cooperative_claim_propose",
    "cooperation_id": ID,
    "unsigned_transaction": "00" * 100,
    "payment_preimage": "04" * 32,
    "public_nonce": NONCE,
    "deadline_at": 1700000000,
    "deadline_height": 1000,
}
READY_REQUEST = {
    "action": "cooperative_claim_ready",
    "challenge": "05" * 32,
    "payment_preimage": "04" * 32,
    "deadline_at": 1700000000,
    "deadline_height": 1000,
}
READY_RESULT = {
    "action": "cooperative_claim_ready",
    "challenge": "05" * 32,
    "status": "ready",
}


@pytest.mark.parametrize(
    ("message_type", "payload", "model"),
    [
        ("action_request", READY_REQUEST, CooperativeClaimReadyRequest),
        ("action_result", READY_RESULT, CooperativeClaimReady),
        ("action_request", PROPOSE, CooperativeClaimPropose),
        (
            "action_result",
            {
                "action": "cooperative_claim_propose",
                "cooperation_id": ID,
                "status": "signed",
                "public_nonce": NONCE,
                "partial_signature": PARTIAL,
            },
            CooperativeClaimSigned,
        ),
        (
            "action_result",
            {"action": "cooperative_claim_propose", "cooperation_id": ID, "status": "declined"},
            CooperativeClaimDeclined,
        ),
        (
            "action_request",
            {
                "action": "cooperative_claim_complete",
                "cooperation_id": ID,
                "partial_signature": PARTIAL,
            },
            CooperativeClaimComplete,
        ),
        (
            "action_result",
            {"action": "cooperative_claim_complete", "cooperation_id": ID, "status": "verified"},
            CooperativeClaimVerified,
        ),
    ],
)
def test_closed_cooperative_shapes_round_trip(
    message_type: str, payload: dict[str, object], model: type
) -> None:
    parsed = parse_cooperative_payload(message_type, canonicalize(payload))  # type: ignore[arg-type]
    assert isinstance(parsed, model)
    assert parsed.model_dump(mode="json") == payload


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("cooperation_id", "ff"),
        ("public_nonce", "02" * 65),
        ("public_nonce", "GG" * 66),
        ("unsigned_transaction", "00" * 59),
        ("unsigned_transaction", "00" * 1001),
        ("unsigned_transaction", "AA" * 100),
        ("deadline_at", True),
        ("deadline_height", -1),
        ("payment_preimage", "00" * 31),
        ("unexpected", "hidden"),
        ("status", "signed"),
    ],
)
def test_malformed_proposal_is_refused(key: str, value: object) -> None:
    payload = {**PROPOSE, key: value}
    with pytest.raises(ValueError, match=r"validation error|request unsupported"):
        parse_cooperative_payload("action_request", canonicalize(payload))


def test_role_of_request_and_result_and_replay_bytes_are_not_conflated() -> None:
    with pytest.raises(ValueError, match="request unsupported"):
        parse_cooperative_payload(
            "action_request",
            canonicalize(
                {"action": "cooperative_claim_propose", "cooperation_id": ID, "status": "declined"}
            ),
        )
    with pytest.raises(ValueError, match="result unsupported"):
        parse_cooperative_payload("action_result", canonicalize(PROPOSE))
    with pytest.raises(ValueError, match="must be an object"):
        parse_cooperative_payload("action_request", b"[]")
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        parse_cooperative_payload(
            "action_request",
            b'{"action":"cooperative_claim_propose","action":"cooperative_claim_complete"}',
        )
    with pytest.raises(ValueError, match="validation error"):
        parse_cooperative_payload(
            "action_result",
            json.dumps(
                {
                    "action": "cooperative_claim_complete",
                    "cooperation_id": ID,
                    "status": "verified",
                    "partial_signature": PARTIAL,
                }
            ).encode(),
        )


def _signed_context(profile: str) -> tuple[ContractTerms, HandshakeInit, HandshakeAccept]:
    fixture = (
        "initial-btc-to-ln-v1.json"
        if profile == "btc-to-ln/v1"
        else "initial-ln-to-btc-no-prepayment-v1.json"
    )
    record = json.loads((FIXTURES / fixture).read_text())
    context = record["verification_context"]
    init_document = context["handshake_init"]
    init_document["required_features"] = [COOPERATIVE_CLAIM_FEATURE]
    init = HandshakeInit.model_validate_json(json.dumps(init_document), strict=True)
    accept_document = context["handshake_accept"]
    accept_document["required_features"] = [COOPERATIVE_CLAIM_FEATURE]
    accept_document["handshake_init_hash"] = handshake_init_hash(init).hex()
    accept = HandshakeAccept.model_validate_json(json.dumps(accept_document), strict=True)
    terms_document = record["contract_terms"]
    terms_document["required_features"] = [COOPERATIVE_CLAIM_FEATURE]
    terms = ContractTerms.model_validate_json(json.dumps(terms_document), strict=True)
    return terms, init, accept


def _envelope(  # noqa: PLR0913 - explicit envelope fields in adversarial fixture
    terms: ContractTerms,
    init: HandshakeInit,
    payload: dict[str, object],
    *,
    sender: str,
    message_type: str = "action_request",
    reply_to: str | None = None,
    message_id: str = "aa" * 32,
) -> Envelope:
    return Envelope.model_validate_json(
        json.dumps(
            {
                "protocol": "rillswap",
                "wire_version": "1",
                "profile_id": terms.profile_id,
                "network_identity": terms.network_identity.model_dump(mode="json"),
                "session_id": init.session_id,
                "message_id": message_id,
                "sender_session_key": sender,
                "sequence": 3,
                "in_reply_to": reply_to,
                "contract_hash": contract_hash(terms).hex(),
                "message_type": message_type,
                "payload": payload,
                "required_features": [COOPERATIVE_CLAIM_FEATURE],
                "extensions": {},
                "signature": "11" * 64,
            }
        ),
        strict=True,
    )


@pytest.mark.parametrize("profile", ["btc-to-ln/v1", "ln-to-btc/v1"])
def test_cooperative_actions_bind_role_feature_and_exact_reply_chain(profile: str) -> None:
    terms, init, accept = _signed_context(profile)
    claimant = (
        init.client_session_xonly_key
        if terms.claimant == "client"
        else accept.provider_session_xonly_key
    )
    cosigner = (
        accept.provider_session_xonly_key
        if terms.claimant == "client"
        else init.client_session_xonly_key
    )
    propose = _envelope(terms, init, PROPOSE, sender=claimant)
    signed = _envelope(
        terms,
        init,
        {
            "action": "cooperative_claim_propose",
            "cooperation_id": ID,
            "status": "signed",
            "public_nonce": NONCE,
            "partial_signature": PARTIAL,
        },
        sender=cosigner,
        message_type="action_result",
        reply_to=propose.message_id,
        message_id="bb" * 32,
    )
    complete = _envelope(
        terms,
        init,
        {
            "action": "cooperative_claim_complete",
            "cooperation_id": ID,
            "partial_signature": PARTIAL,
        },
        sender=claimant,
        message_id="cc" * 32,
    )
    verified = _envelope(
        terms,
        init,
        {
            "action": "cooperative_claim_complete",
            "cooperation_id": ID,
            "status": "verified",
        },
        sender=cosigner,
        message_type="action_result",
        reply_to=complete.message_id,
        message_id="dd" * 32,
    )
    assert isinstance(
        check_cooperative_action_context(propose, terms, init, accept), CooperativeClaimPropose
    )
    assert isinstance(
        check_cooperative_action_context(signed, terms, init, accept, prior_request=propose),
        CooperativeClaimSigned,
    )
    assert isinstance(
        check_cooperative_action_context(complete, terms, init, accept, prior_request=propose),
        CooperativeClaimComplete,
    )
    assert isinstance(
        check_cooperative_action_context(verified, terms, init, accept, prior_request=complete),
        CooperativeClaimVerified,
    )

    for tampered in (
        propose.model_copy(update={"sender_session_key": cosigner}),
        propose.model_copy(update={"required_features": ()}),
        propose.model_copy(
            update={"required_features": (COOPERATIVE_CLAIM_FEATURE, "unknown-feature/v1")}
        ),
        propose.model_copy(update={"contract_hash": "ff" * 32}),
        propose.model_copy(update={"session_id": "ff" * 32}),
    ):
        with pytest.raises(ValueError, match=r"sender role|signed feature"):
            check_cooperative_action_context(tampered, terms, init, accept)
    for tampered in (
        signed.model_copy(update={"in_reply_to": "ff" * 32}),
        signed.model_copy(update={"sender_session_key": claimant}),
        signed.model_copy(update={"payload": {**signed.payload, "cooperation_id": "ff" * 32}}),
    ):
        with pytest.raises(ValueError, match=r"exact request|sender role|different attempt"):
            check_cooperative_action_context(tampered, terms, init, accept, prior_request=propose)
    with pytest.raises(ValueError, match="different signed request"):
        check_cooperative_action_context(
            signed,
            terms,
            init,
            accept,
            prior_request=propose.model_copy(update={"contract_hash": "ff" * 32}),
        )
    for wrong_prior in (
        propose.model_copy(update={"in_reply_to": "ee" * 32}),
        propose.model_copy(
            update={"required_features": (COOPERATIVE_CLAIM_FEATURE, "unknown-feature/v1")}
        ),
    ):
        with pytest.raises(ValueError, match="different signed request"):
            check_cooperative_action_context(signed, terms, init, accept, prior_request=wrong_prior)
    with pytest.raises(ValueError, match="prior proposal"):
        check_cooperative_action_context(complete, terms, init, accept)
    with pytest.raises(ValueError, match="exact request"):
        check_cooperative_action_context(verified, terms, init, accept, prior_request=propose)


@pytest.mark.parametrize("profile", SHARED_CYCLE["profiles"], ids=lambda p: p["profile_id"])
@pytest.mark.parametrize(
    "variation",
    [None, *SHARED_CYCLE["invalid"]],
    ids=lambda v: "valid cycle" if v is None else v["name"],
)
def test_shared_cooperative_wire_cycle(profile: dict, variation: dict | None) -> None:
    terms, init, accept = _signed_context(profile["profile_id"])
    session_keys = {
        "client": init.client_session_xonly_key,
        "provider": accept.provider_session_xonly_key,
    }
    messages = copy.deepcopy(SHARED_CYCLE["messages"])
    if variation is not None:
        target = messages[variation["message"]]
        path = variation["field"].split(".")
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = variation["replacement"]
    envelopes = {}
    for name, message in messages.items():
        role = profile[message["sender_role"] + "_role"]
        envelopes[name] = _envelope(
            terms,
            init,
            message["payload"],
            sender=session_keys[role],
            message_type=message["message_type"],
            reply_to=message["in_reply_to"],
            message_id=message["message_id"],
        ).model_copy(update={"required_features": tuple(message["required_features"])})
    if variation is not None:
        name = variation["message"]
        prior = messages[name]["prior_request"]
        with pytest.raises(
            ValueError,
            match=(
                r"sender role|signed feature|exact request|different attempt|"
                r"prior proposal|validation error"
            ),
        ):
            check_cooperative_action_context(
                envelopes[name],
                terms,
                init,
                accept,
                prior_request=envelopes[prior] if prior else None,
            )
    else:
        for name, envelope in envelopes.items():
            prior = messages[name]["prior_request"]
            parsed = check_cooperative_action_context(
                envelope, terms, init, accept, prior_request=envelopes[prior] if prior else None
            )
            assert parsed.model_dump(mode="json") == messages[name]["payload"]


def test_legacy_signed_contract_does_not_authorize_cooperative_action() -> None:
    terms, init, accept = _signed_context("btc-to-ln/v1")
    proposal = _envelope(terms, init, PROPOSE, sender=accept.provider_session_xonly_key)
    with pytest.raises(ValueError, match="not bound to both"):
        check_cooperative_action_context(
            proposal, terms.model_copy(update={"required_features": ()}), init, accept
        )
    with pytest.raises(ValueError, match="not bound to both"):
        check_cooperative_action_context(
            proposal, terms, init, accept.model_copy(update={"required_features": ()})
        )


def test_readiness_is_exact_feature_bound_provider_request_and_client_echo() -> None:
    terms, init, accept = _signed_context("btc-to-ln/v1")
    request = _envelope(terms, init, READY_REQUEST, sender=accept.provider_session_xonly_key)
    result = _envelope(
        terms,
        init,
        READY_RESULT,
        sender=init.client_session_xonly_key,
        message_type="action_result",
        reply_to=request.message_id,
        message_id="bb" * 32,
    )
    assert isinstance(
        check_cooperative_action_context(request, terms, init, accept),
        CooperativeClaimReadyRequest,
    )
    assert isinstance(
        check_cooperative_action_context(result, terms, init, accept, prior_request=request),
        CooperativeClaimReady,
    )
    for tampered in (
        result.model_copy(update={"in_reply_to": "ff" * 32}),
        result.model_copy(update={"sender_session_key": accept.provider_session_xonly_key}),
        result.model_copy(update={"payload": {**READY_RESULT, "challenge": "ff" * 32}}),
        result.model_copy(update={"required_features": ()}),
        result.model_copy(update={"session_id": "ff" * 32}),
    ):
        with pytest.raises(ValueError, match=r"readiness|sender role|signed feature"):
            check_cooperative_action_context(tampered, terms, init, accept, prior_request=request)
    with pytest.raises(ValueError, match="exact request"):
        check_cooperative_action_context(
            result,
            terms,
            init,
            accept,
            prior_request=_envelope(terms, init, PROPOSE, sender=accept.provider_session_xonly_key),
        )
    with pytest.raises(ValueError, match="sender role"):
        check_cooperative_action_context(
            request.model_copy(update={"sender_session_key": init.client_session_xonly_key}),
            terms,
            init,
            accept,
        )
    for payload in (
        {"action": "cooperative_claim_propose", "cooperation_id": ID, "status": "declined"},
        {"action": "cooperative_claim_complete", "cooperation_id": ID, "status": "verified"},
    ):
        incompatible = result.model_copy(update={"payload": payload})
        with pytest.raises(ValueError, match="different attempt"):
            check_cooperative_action_context(
                incompatible, terms, init, accept, prior_request=request
            )
    reverse_terms, reverse_init, reverse_accept = _signed_context("ln-to-btc/v1")
    reverse = _envelope(
        reverse_terms,
        reverse_init,
        READY_REQUEST,
        sender=reverse_init.client_session_xonly_key,
    )
    with pytest.raises(ValueError, match="only for provider claims"):
        check_cooperative_action_context(reverse, reverse_terms, reverse_init, reverse_accept)
    reverse_reply = _envelope(
        reverse_terms,
        reverse_init,
        READY_RESULT,
        sender=reverse_accept.provider_session_xonly_key,
        message_type="action_result",
        reply_to=reverse.message_id,
    )
    with pytest.raises(ValueError, match="exact request"):
        check_cooperative_action_context(
            reverse_reply, reverse_terms, reverse_init, reverse_accept, prior_request=reverse
        )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("challenge", "aa" * 31),
        ("challenge", "AA" * 32),
        ("deadline_at", True),
        ("deadline_height", "1000"),
        ("status", "ready"),
        ("unexpected", "ignored"),
    ],
)
def test_readiness_request_rejects_malformed_payload(key: str, value: object) -> None:
    with pytest.raises(ValueError, match=r"validation error|request unsupported"):
        parse_cooperative_payload("action_request", canonicalize({**READY_REQUEST, key: value}))
    with pytest.raises(ValueError, match="result unsupported"):
        parse_cooperative_payload("action_result", canonicalize(READY_REQUEST))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("challenge", "aa" * 31),
        ("challenge", "AA" * 32),
        ("status", "signed"),
        ("unexpected", "ignored"),
        ("deadline_at", 1700000000),
    ],
)
def test_readiness_result_rejects_malformed_payload(key: str, value: object) -> None:
    with pytest.raises(ValueError, match=r"validation error|result unsupported"):
        parse_cooperative_payload("action_result", canonicalize({**READY_RESULT, key: value}))
