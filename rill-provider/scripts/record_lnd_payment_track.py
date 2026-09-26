"""Operator-invoked, regtest-only payment tracking evidence (never authority)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from pydantic import ValidationError
from rill_core.wire.types import NetworkIdentity

from rill_provider.lnd_payment_observation import LndObservationError, LndPaymentObserver
from rill_provider.payment_journal import OutgoingPaymentJournal, PaymentJournalError
from rill_provider.payment_track_recording import record_payment_track

MAX_NETWORK_BYTES = 4096


def _network(path: Path) -> NetworkIdentity:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        content = os.read(descriptor, MAX_NETWORK_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(content) > MAX_NETWORK_BYTES:
        raise ValueError("network identity too large")
    return NetworkIdentity.model_validate_json(content)


def main(argv: list[str] | None = None) -> int:
    """Refuse unknown state; make no payment or startup decision."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--network-identity", type=Path, required=True)
    parser.add_argument("--backend-identity", required=True)
    parser.add_argument("--idempotency-key", required=True)
    parser.add_argument("--lnd-host", required=True)
    parser.add_argument("--lnd-port", type=int, required=True)
    parser.add_argument("--tls-cert", type=Path, required=True)
    parser.add_argument("--read-macaroon", type=Path, required=True)
    parser.add_argument("--evidence-out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        network = _network(args.network_identity)
        journal = OutgoingPaymentJournal.open_existing(args.journal, network, args.backend_identity)
        observer = LndPaymentObserver(
            host=args.lnd_host,
            port=args.lnd_port,
            tls_certificate_path=args.tls_cert,
            read_macaroon_path=args.read_macaroon,
            network=network,
        )
        recorded = record_payment_track(journal, args.idempotency_key, observer, args.evidence_out)
    except (OSError, ValueError, ValidationError, PaymentJournalError, LndObservationError):
        sys.stderr.write("Payment observation unavailable or unrecorded; no action authority\n")
        return 2
    sys.stdout.write(
        f"Recorded {len(recorded.observations)} diagnostic observations; no action authority\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
