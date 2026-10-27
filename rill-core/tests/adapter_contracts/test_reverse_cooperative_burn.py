"""Reverse pre-nonce reservations consume an attempt, never restore signing."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING

import pytest
import test_reverse_disclosure_reservation as disclosure_cases

from rill_core.errors import ValidationError
from rill_core.recovery import (
    REVERSE_COOPERATIVE_RESERVATION_EXTENSION as BURN,
)
from rill_core.recovery import (
    REVERSE_DISCLOSURE_EXTENSION as DISCLOSURE,
)
from rill_core.recovery import (
    REVERSE_FALLBACK_EXTENSION as FALLBACK,
)
from rill_core.wire.canonical import canonicalize
from rill_core.wire.messages import Envelope

if TYPE_CHECKING:
    from test_reverse_disclosure_reservation import ReservedDisclosure

pytestmark = disclosure_cases.pytestmark
reservation = disclosure_cases.reservation


def _burn(reservation: ReservedDisclosure) -> dict:
    document = copy.deepcopy(reservation.prior)
    document["extensions"][BURN] = {
        "funding_binding_hash": document["extensions"][FALLBACK]["funding_binding_hash"],
        "cooperation_id": "ff" * 32,
    }
    return document


def test_burn_then_disclosure_preserves_the_fallback_and_report(
    reservation: ReservedDisclosure,
) -> None:
    burned = _burn(reservation)
    assert reservation.successor(reservation.prior, burned) == reservation.inspect(
        reservation.prior
    )
    disclosed = copy.deepcopy(reservation.next)
    disclosed["extensions"][BURN] = burned["extensions"][BURN]
    assert reservation.successor(burned, disclosed) == reservation.inspect(disclosed)


@pytest.mark.parametrize(
    "variation", ["missing id", "extra", "null", "zero", "binding", "no fallback"]
)
def test_partial_or_invalid_burn_fails_closed(
    reservation: ReservedDisclosure, variation: str
) -> None:
    document = _burn(reservation)
    marker = document["extensions"][BURN]
    if variation == "missing id":
        del marker["cooperation_id"]
    elif variation == "extra":
        marker["signed"] = True
    elif variation == "null":
        document["extensions"][BURN] = None
    elif variation == "zero":
        marker["cooperation_id"] = "00" * 32
    elif variation == "binding":
        marker["funding_binding_hash"] = "aa" * 32
    else:
        del document["extensions"][FALLBACK]
    with pytest.raises(ValidationError):
        reservation.inspect(document)


@pytest.mark.parametrize(
    "variation",
    [
        "changed id",
        "removed",
        "simultaneous fallback",
        "simultaneous disclosure",
        "after disclosure",
    ],
)
def test_burn_is_append_once_and_has_its_own_predecessor(
    reservation: ReservedDisclosure, variation: str
) -> None:
    previous, candidate = _burn(reservation), _burn(reservation)
    if variation == "changed id":
        candidate["extensions"][BURN]["cooperation_id"] = "ee" * 32
    elif variation == "removed":
        del candidate["extensions"][BURN]
    elif variation == "simultaneous fallback":
        previous = copy.deepcopy(reservation.prior)
        del previous["extensions"][FALLBACK]
    elif variation == "simultaneous disclosure":
        previous = reservation.prior
        candidate["extensions"][DISCLOSURE] = reservation.next["extensions"][DISCLOSURE]
    else:
        previous = reservation.next
        candidate = copy.deepcopy(reservation.next)
        candidate["extensions"][BURN] = _burn(reservation)["extensions"][BURN]
    with pytest.raises(ValidationError):
        reservation.successor(previous, candidate)


def test_disclosure_must_match_the_durably_burned_identifier(
    reservation: ReservedDisclosure,
) -> None:
    document = copy.deepcopy(reservation.next)
    document["extensions"][BURN] = _burn(reservation)["extensions"][BURN]
    proposal = document["extensions"][DISCLOSURE]["proposal"]
    proposal["payload"]["cooperation_id"] = "ee" * 32
    proposal = Envelope.model_validate_json(canonicalize(proposal), strict=True)
    document["extensions"][DISCLOSURE]["proposal"] = reservation.sign(proposal).model_dump(
        mode="json"
    )
    with pytest.raises(ValidationError):
        reservation.inspect(document)
