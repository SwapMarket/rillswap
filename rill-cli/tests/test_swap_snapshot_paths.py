"""Paid recovery is a new create-only successor, never a replacement file."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from rill_core.recovery import COOPERATIVE_RESERVATION_EXTENSION, REVERSE_FALLBACK_EXTENSION

from rill_cli.publication import RecoveryPublicationError, publish_new_ciphertext
from rill_cli.swap_command import _snapshot_path

if TYPE_CHECKING:
    from pathlib import Path


def _snapshot(*, funded: bool, paid: bool) -> bytes:
    return json.dumps(
        {
            "funding_history": [{"binding": "fixture"}] if funded else [],
            "monotonic_knowledge": {"preimage_known": paid},
        }
    ).encode()


def test_initial_funded_and_paid_snapshots_have_distinct_destinations(tmp_path: Path) -> None:
    output = tmp_path / "swap.age"
    initial, funded, paid = (
        _snapshot(funded=False, paid=False),
        _snapshot(funded=True, paid=False),
        _snapshot(funded=True, paid=True),
    )
    assert _snapshot_path(output, initial, None) == output
    assert _snapshot_path(output, funded, initial) == tmp_path / "swap.age.funded"
    assert _snapshot_path(output, paid, funded) == tmp_path / "swap.age.paid"
    # Reverse swaps already know the preimage, but still publish their first
    # funding successor to the funded path.
    assert _snapshot_path(output, paid, _snapshot(funded=False, paid=True)) == (
        tmp_path / "swap.age.funded"
    )
    with pytest.raises(ValueError, match="unsupported recovery snapshot transition"):
        _snapshot_path(output, paid, paid)


def test_paid_destination_collision_preserves_all_existing_snapshots(tmp_path: Path) -> None:
    output = tmp_path / "swap.age"
    funded, paid = _snapshot(funded=True, paid=False), _snapshot(funded=True, paid=True)
    target = _snapshot_path(output, paid, funded)
    original = {output: b"initial", tmp_path / "swap.age.funded": b"funded", target: b"paid"}
    for path, content in original.items():
        path.write_bytes(content)
    with pytest.raises(RecoveryPublicationError):
        publish_new_ciphertext(target, b"new ciphertext", verify_from_disk=lambda raw: raw)
    assert {path: path.read_bytes() for path in original} == original


def test_changed_funding_cannot_route_to_paid(tmp_path: Path) -> None:
    funded = _snapshot(funded=True, paid=False)
    paid = json.loads(_snapshot(funded=True, paid=True))
    paid["funding_history"] = [{"binding": "another output"}]
    with pytest.raises(ValueError, match="unsupported recovery snapshot transition"):
        _snapshot_path(tmp_path / "swap.age", json.dumps(paid).encode(), funded)


def test_cooperative_reservation_has_one_distinct_destination(tmp_path: Path) -> None:
    paid = json.loads(_snapshot(funded=True, paid=True))
    paid["extensions"] = {}
    reserved = {**paid, "extensions": {COOPERATIVE_RESERVATION_EXTENSION: {"version": 1}}}
    paid_bytes, reserved_bytes = json.dumps(paid).encode(), json.dumps(reserved).encode()
    assert _snapshot_path(tmp_path / "swap.age", reserved_bytes, paid_bytes) == (
        tmp_path / "swap.age.cooperating"
    )
    with pytest.raises(ValueError, match="unsupported recovery snapshot transition"):
        _snapshot_path(tmp_path / "swap.age", reserved_bytes, reserved_bytes)
    reserved["funding_history"] = [{"binding": "other"}]
    with pytest.raises(ValueError, match="unsupported recovery snapshot transition"):
        _snapshot_path(tmp_path / "swap.age", json.dumps(reserved).encode(), paid_bytes)


def test_reverse_fallback_routes_to_a_distinct_create_only_sibling(tmp_path: Path) -> None:
    funded = json.loads(_snapshot(funded=True, paid=True))
    funded.update(profile_id="ln-to-btc/v1", extensions={})
    prepared = {**funded, "extensions": {REVERSE_FALLBACK_EXTENSION: {"version": 1}}}
    prior, candidate = json.dumps(funded).encode(), json.dumps(prepared).encode()
    assert _snapshot_path(tmp_path / "swap.age", candidate, prior) == tmp_path / "swap.age.fallback"
    with pytest.raises(ValueError, match="unsupported recovery snapshot transition"):
        _snapshot_path(tmp_path / "swap.age", candidate, candidate)
    prepared["funding_history"] = [{"binding": "another output"}]
    with pytest.raises(ValueError, match="unsupported recovery snapshot transition"):
        _snapshot_path(tmp_path / "swap.age", json.dumps(prepared).encode(), prior)
