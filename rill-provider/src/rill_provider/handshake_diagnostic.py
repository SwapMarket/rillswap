"""Explicit real-crypto static handshake diagnostic, never session admission.

No backend, transport, database, signer, or key store is accessed. A valid
historical transcript passes again and grants no action or replay authority.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from rill_core.errors import ValidationError
from rill_core.wire import verify_static_handshake_transcript
from rill_crypto import Context

if TYPE_CHECKING:
    from rill_core.wire.types import NetworkIdentity, ProfileId, XOnlyKey


class HandshakeDiagnosticUnavailableError(Exception):
    """The requested native check could not finish, with no admission claim."""


def verify_handshake_diagnostic(  # noqa: PLR0913 - explicit trust inputs
    init_document: bytes,
    accept_document: bytes,
    confirm_document: bytes,
    *,
    expected_provider_identity: XOnlyKey,
    expected_profile: ProfileId,
    expected_network: NetworkIdentity,
    supported_features: frozenset[str],
    supported_encryption_suites: frozenset[str],
    supported_capabilities: frozenset[str],
    native_library_path: Path,
) -> bytes:
    """Verify pinned historical signatures; return only the transcript digest.

    The caller supplies independent expected identity/network and an absolute
    trusted library path. No environment or discovery fallback is permitted.
    Static success proves neither key custody nor live receipt, order, or
    durable replay disposition. None of these inputs authorizes a payment.
    """
    if not isinstance(native_library_path, Path) or not native_library_path.is_absolute():
        raise HandshakeDiagnosticUnavailableError("native handshake diagnostic unavailable")
    try:
        with Context(library_path=native_library_path) as crypto:
            return verify_static_handshake_transcript(
                init_document,
                accept_document,
                confirm_document,
                expected_provider_identity=expected_provider_identity,
                expected_profile=expected_profile,
                expected_network=expected_network,
                supported_features=supported_features,
                supported_encryption_suites=supported_encryption_suites,
                supported_capabilities=supported_capabilities,
                crypto=crypto,
            )
    except ValidationError:
        raise
    except Exception:  # noqa: BLE001, S110 - do not expose library path or native error
        pass
    raise HandshakeDiagnosticUnavailableError("native handshake diagnostic unavailable")
