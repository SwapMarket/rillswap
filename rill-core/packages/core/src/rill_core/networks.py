"""Explicit supported Bitcoin identities, independent of permission to move funds.

These are consensus/serialization capabilities, not release authorization.
Network labels, matching address prefixes, and a shared genesis alone are not
sufficient, notably for custom signets. Live adapters must attest their actual
backends and apply their own release gates before any financial effect.
"""

from __future__ import annotations

from rill_core.errors import ValidationError
from rill_core.wire.types import NetworkIdentity

REGTEST_CONSENSUS_PROFILE = "bitcoin-core-v30.0-regtest-default"
PUBLIC_CONSENSUS_PROFILE = "bitcoin-core-v30.0"
SUPPORTED_CONSENSUS_PROFILES = frozenset({REGTEST_CONSENSUS_PROFILE, PUBLIC_CONSENSUS_PROFILE})
DEFAULT_SIGNET_CHALLENGE = (
    "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be43"
    "0210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"
)
_GENESIS = {
    "mainnet": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    "signet": "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
    "testnet4": "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
    "regtest": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
}


def require_supported_network(network: NetworkIdentity) -> None:
    """Require default signet, testnet4, mainnet, or namespaced default regtest.

    Existing wire parsers intentionally retain older and custom identities for
    inspection. This narrower execution policy never treats an unknown identity
    as a supported chain or upgrades an old record implicitly.
    """
    if not isinstance(network, NetworkIdentity):
        raise ValidationError("unsupported Bitcoin network identity")
    profile = REGTEST_CONSENSUS_PROFILE if network.name == "regtest" else PUBLIC_CONSENSUS_PROFILE
    challenge = DEFAULT_SIGNET_CHALLENGE if network.name == "signet" else None
    if (
        network.family != "bitcoin"
        or network.name not in _GENESIS
        or network.genesis_hash != _GENESIS[network.name]
        or network.consensus_profile != profile
        or network.signet_challenge != challenge
        or (network.name == "regtest" and not network.deployment_namespace)
        or (network.name != "regtest" and network.deployment_namespace is not None)
    ):
        raise ValidationError("unsupported Bitcoin network identity")
