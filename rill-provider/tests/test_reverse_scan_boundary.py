"""Funding depth and branch continuity are authenticated before scan authority."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from test_core_tx_bytes import _context
from test_core_wallet_funding import _by_method, _cookie, _server

from rill_provider.core_tx_bytes import CoreProtocolError, CoreTransactionReader

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    "fault", [None, "unconfirmed", "wrong-height", "reorg", "wrong-tx", "bad-parent"]
)
def test_funding_boundary_requires_canonical_confirmed_identity(
    tmp_path: Path, fault: str | None
) -> None:
    _, _, network = _context()
    txid, block, parent = "51" * 32, "ab" * 32, "cd" * 32
    header = {"hash": block, "height": 101, "confirmations": 2, "previousblockhash": parent}
    replies = {
        "getrawtransaction": {"txid": txid, "blockhash": block},
        "getblockheader": header,
        "getblockhash": block,
    }
    if fault == "unconfirmed":
        header["confirmations"] = 0
    elif fault == "wrong-height":
        header["height"] = True
    elif fault == "reorg":
        replies["getblockhash"] = "ef" * 32
    elif fault == "wrong-tx":
        replies["getrawtransaction"]["txid"] = "61" * 32
    elif fault == "bad-parent":
        header["previousblockhash"] = "broken"
    with _server(_by_method(replies), []) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        if fault is None:
            assert reader.funding_scan_boundary(txid, 2) == (100, parent)
        else:
            with pytest.raises(CoreProtocolError, match="inclusion"):
                reader.funding_scan_boundary(txid, 2)
