"""Modern network identities support offline construction, not live funding."""

from __future__ import annotations

from pathlib import Path

import pytest
from test_funding import _candidate
from test_unilateral import _first_context, _keys

from rill_core.errors import ValidationError
from rill_core.networks import require_supported_network
from rill_core.settlement import UnilateralAuthorization, authorize_funding_transaction
from rill_core.settlement.unilateral import build_unilateral_spend
from rill_core.wire.types import NetworkIdentity

NETWORKS = Path(__file__).parents[3] / "rill-docs" / "networks"
NAMES = ("mainnet", "signet", "testnet4", "regtest-rillswap-e2e-v1")


def _network(name: str) -> NetworkIdentity:
    return NetworkIdentity.model_validate_json((NETWORKS / f"{name}.json").read_bytes())


@pytest.mark.parametrize("name", NAMES)
def test_published_modern_identities_match_execution_policy(name: str) -> None:
    require_supported_network(_network(name))


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize(
    "field", ["family", "genesis_hash", "consensus_profile", "signet_challenge"]
)
def test_network_labels_never_override_changed_consensus_identity(name: str, field: str) -> None:
    value = {
        "family": "non-bitcoin",
        "genesis_hash": "00" * 32,
        "consensus_profile": "unknown",
        "signet_challenge": "51",
    }
    changed = _network(name).model_copy(update={field: value[field]})
    with pytest.raises(ValidationError, match="unsupported Bitcoin network identity"):
        require_supported_network(changed)


def test_legacy_testnet_and_custom_signet_are_not_silently_enabled() -> None:
    with pytest.raises(ValidationError, match="unsupported Bitcoin network identity"):
        require_supported_network(_network("testnet3"))
    custom = _network("signet").model_copy(update={"deployment_namespace": "private"})
    with pytest.raises(ValidationError, match="unsupported Bitcoin network identity"):
        require_supported_network(custom)


def test_regtest_requires_explicit_namespace() -> None:
    changed = _network("regtest-rillswap-e2e-v1").model_copy(update={"deployment_namespace": None})
    with pytest.raises(ValidationError, match="unsupported Bitcoin network identity"):
        require_supported_network(changed)


@pytest.mark.parametrize("name", NAMES)
def test_funding_byte_authorization_for_supported_networks(name: str) -> None:
    raw, plan, terms, keys = _candidate()
    terms = terms.model_copy(update={"network_identity": _network(name)})
    authorized = authorize_funding_transaction(raw, terms, plan, keys=keys)
    assert authorized.raw_transaction == raw
    assert authorized.contract_value_sat == int(terms.economics.contract_amount_sat)


@pytest.mark.parametrize("name", NAMES)
def test_refund_construction_for_supported_networks(name: str) -> None:
    case, terms, funding = _first_context()
    terms = terms.model_copy(update={"network_identity": _network(name)})
    authorization = UnilateralAuthorization.from_terms(
        terms, funding, "refund", keys=_keys(terms, case)
    )
    spend = build_unilateral_spend(authorization, fee_sat=100)
    assert spend.output_value_sat == funding.value_sat - 100
    assert authorization.lock_time == terms.refund_lock_height


def test_funding_rejects_spoofed_public_genesis_before_crypto() -> None:
    raw, plan, terms, keys = _candidate()
    network = _network("mainnet").model_copy(update={"genesis_hash": "00" * 32})
    terms = terms.model_copy(update={"network_identity": network})
    with pytest.raises(ValidationError, match="unsupported Bitcoin network identity"):
        authorize_funding_transaction(raw, terms, plan, keys=keys)
