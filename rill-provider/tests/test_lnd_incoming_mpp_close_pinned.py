"""A hostile payer force-closes with a held MPP payment while the receiver restarts.

Pinned Core and LND only. Payer ``a`` pays receiver ``b``'s hold invoice in two
shards with different expiries, then force-closes the only channel while both
HTLCs are held. ``b`` is stopped while the close confirms and restarts. With a
settlement ``b`` must still collect both HTLC outputs on chain with the
preimage; without one the payer times them out. This is an ordinary hostile
force close, not the pending-commitment race of the LND advisory (0.18.0).
"""

from __future__ import annotations

import os
from importlib import import_module
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

# Appended inside CHANNEL_SETUP's Core client block, hence the indentation.
SCENARIO = """
    from rill_provider.lnd_hold_invoice import LndHoldInvoices
    from rill_provider.lnd_invoice_decode import LndInvoiceDecoder
    settle_after_close = globals().get('SETTLE_AFTER_CLOSE', False)
    print('PHASE: hostile_credentials', file=sys.stderr)
    network = NetworkIdentity.model_validate(json.loads(
        Path('/work/provider/tests/fixtures/initial-btc-to-ln-v1.json').read_text()
    )['contract_terms']['network_identity'])
    credentials = Path(tempfile.mkdtemp(dir='/tmp'))
    def baked(name, permissions):
        macaroon = bytes.fromhex(call(b, b_secret, 'BakeMacaroon', ln.BakeMacaroonRequest,
            ln.BakeMacaroonResponse, ln.BakeMacaroonRequest(permissions=[
                ln.MacaroonPermission(entity=entity, action=action)
                for entity, action in permissions],
                root_key_id=0, allow_external_permissions=False)).macaroon)
        fd = os.open(credentials / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600)
        with os.fdopen(fd, 'wb') as target:
            target.write(macaroon)
        return credentials / name
    decoder = LndInvoiceDecoder(host='127.0.0.1', port=10010,
        tls_certificate_path='/work/public/b.cert',
        macaroon_path=baked('decode.macaroon', [('offchain', 'read')]), network=network)
    held = LndHoldInvoices(host='127.0.0.1', port=10010,
        tls_certificate_path='/work/public/b.cert',
        macaroon_path=baked('hold.macaroon',
            [('invoices', 'read'), ('invoices', 'write'), ('info', 'read')]),
        network=network)

    def synced(attempts=150):
        tip = rpc('getblockcount', [])
        for _ in range(attempts):
            infos = [call(node, secret, 'GetInfo', ln.GetInfoRequest, ln.GetInfoResponse,
                ln.GetInfoRequest()) for node, secret in ((a, a_secret), (b, b_secret))]
            if all(info.block_height == tip and info.synced_to_chain for info in infos):
                return tip
            time.sleep(0.2)
        raise AssertionError('LND nodes did not reach the Core tip')

    print('PHASE: hostile_hold_invoice', file=sys.stderr)
    preimage = secrets.token_bytes(32)
    payment_hash = hashlib.sha256(preimage).digest()
    total = 200_000_000
    hold = unary(b, '/invoicesrpc.Invoices/AddHoldInvoice', inv.AddHoldInvoiceRequest,
        inv.AddHoldInvoiceResp)(inv.AddHoldInvoiceRequest(hash=payment_hash, value_msat=total,
        expiry=3600, cltv_expiry=40), metadata=metadata(b_secret), timeout=5)
    binding = decoder.decode(hold.payment_request)
    assert binding.payment_hash == payment_hash.hex() and binding.amount_msat == str(total)
    assert binding.payee_compressed_pubkey == b_key and binding.min_final_cltv_delta == 40

    height = synced()
    send = unary(a, '/routerrpc.Router/SendToRouteV2', router.SendToRouteRequest, ln.HTLCAttempt)
    def shard(amount, expiry):
        hop = ln.Hop(chan_id=views[0][0].chan_id, pub_key=b_key, amt_to_forward_msat=amount,
            expiry=expiry, tlv_payload=True, mpp_record=ln.MPPRecord(
                payment_addr=hold.payment_addr, total_amt_msat=total))
        route = ln.Route(total_time_lock=expiry, total_amt_msat=amount, hops=[hop])
        return send.future(router.SendToRouteRequest(payment_hash=payment_hash, route=route),
            metadata=metadata(a_secret), timeout=420)
    def observed(state_name, held_msat):
        for _ in range(100):
            assert not any(future.done() for future in shards), 'a shard resolved early'
            seen = held.observe_bound_invoice(binding, deadline=time.monotonic() + 5)
            if seen.status.state == state_name and seen.status.held_msat == held_msat:
                return seen
            time.sleep(0.2)
        raise AssertionError('hold invoice did not reach ' + state_name)

    print('PHASE: hostile_first_shard', file=sys.stderr)
    shards = [shard(80_000_000, height + 144)]
    observed('OPEN', 80_000_000)
    print('PHASE: hostile_partial_refused', file=sys.stderr)
    try:
        held.settle_bound_invoice(binding, preimage.hex(), deadline=time.monotonic() + 5,
            submission_allowed=lambda: True)
    except LndProtocolError as error:
        assert 'not accepted as agreed' in str(error)
    else:
        raise AssertionError('a partial MPP set was settled')

    print('PHASE: hostile_second_shard', file=sys.stderr)
    shards.append(shard(120_000_000, height + 160))
    accepted = observed('ACCEPTED', total)
    parts = sorted([htlc.amount_msat, htlc.expiry_height] for htlc in accepted.status.htlcs)
    assert parts == [[80_000_000, height + 144], [120_000_000, height + 160]]
    assert accepted.status.earliest_expiry_height == height + 144

    print('PHASE: hostile_force_close', file=sys.stderr)
    closing = a.unary_stream('/lnrpc.Lightning/CloseChannel',
        request_serializer=ln.CloseChannelRequest.SerializeToString,
        response_deserializer=ln.CloseStatusUpdate.FromString)(
        ln.CloseChannelRequest(channel_point=point, force=True),
        metadata=metadata(a_secret), timeout=60)
    assert next(closing).WhichOneof('update') == 'close_pending'
    closing.cancel()
    for _ in range(100):
        close_txid = rpc('gettxspendingprevout',
            [[{'txid': txid, 'vout': point.output_index}]])[0].get('spendingtxid')
        if close_txid:
            break
        time.sleep(0.2)
    else:
        raise AssertionError('force close not in the mempool')
    by_value = {output['value']: output['n']
        for output in rpc('getrawtransaction', [close_txid, True])['vout']}
    # Outpoint -> first height whose block may include the payer's timeout spend.
    htlcs = {(close_txid, by_value[Decimal('0.00080000')]): height + 145,
             (close_txid, by_value[Decimal('0.00120000')]): height + 161}

    print('PHASE: hostile_receiver_stop', file=sys.stderr)
    assert source_wallet_password is not None
    call(b, b_secret, 'StopDaemon', ln.StopRequest, ln.StopResponse, ln.StopRequest())
    b.close()
    b = dial(Path('/work/public/b.cert').read_bytes(), 10010)
    get_state = unary(b, '/lnrpc.State/GetState', state.GetStateRequest, state.GetStateResponse)
    def reached(expected):
        for _ in range(300):
            try:
                if get_state(state.GetStateRequest(), timeout=1).state == expected:
                    return
            except grpc.RpcError:
                pass
            time.sleep(0.1)
        raise AssertionError('receiver restart stalled')
    reached(state.LOCKED)
    print('PHASE: hostile_close_confirms_offline', file=sys.stderr)
    assert len(rpc('generatetoaddress', [1, mining_address], wallet='fund')) == 1
    for close_txid, vout in htlcs:
        assert rpc('gettxout', [close_txid, vout, False])['confirmations'] == 1
    print('PHASE: hostile_receiver_unlock', file=sys.stderr)
    unary(b, '/lnrpc.WalletUnlocker/UnlockWallet', unlock.UnlockWalletRequest,
        unlock.UnlockWalletResponse)(unlock.UnlockWalletRequest(
        wallet_password=source_wallet_password, recovery_window=0, stateless_init=True),
        timeout=30)
    reached(state.SERVER_ACTIVE)
    synced()
    print('PHASE: hostile_receiver_held', file=sys.stderr)
    after = held.observe_bound_invoice(binding, deadline=time.monotonic() + 5)
    assert after.status.state == 'ACCEPTED'
    assert sorted([htlc.amount_msat, htlc.expiry_height] for htlc in after.status.htlcs) == parts

    spends = {}
    def mine_and_scan():
        block = rpc('getblock', [rpc('generatetoaddress', [1, mining_address],
            wallet='fund')[0], 2])
        for transaction in block['tx']:
            for spent in transaction['vin']:
                key = (spent.get('txid'), spent.get('vout'))
                if key in htlcs:
                    spends[key] = {'height': block['height'],
                        'preimage': preimage.hex() in spent.get('txinwitness', [])}
        synced()
    def resolve(limit):
        for _ in range(limit):
            tip = rpc('getblockcount', [])
            pending = [key for key in htlcs if key not in spends]
            if not pending:
                return
            due = [{'txid': key[0], 'vout': key[1]} for key in pending
                if settle_after_close or htlcs[key] <= tip + 1]
            for _ in range(25 if due else 0):  # let the sweeper broadcast first
                if all(entry.get('spendingtxid')
                        for entry in rpc('gettxspendingprevout', [due])):
                    break
                time.sleep(0.2)
            mine_and_scan()
        assert set(spends) == set(htlcs), 'HTLC outputs not resolved on chain'

    if settle_after_close:
        print('PHASE: hostile_settle', file=sys.stderr)
        held.settle_bound_invoice(binding, preimage.hex(), deadline=time.monotonic() + 10,
            submission_allowed=lambda: True)
        held.observe_bound_settled_invoice(binding, deadline=time.monotonic() + 5)
        print('PHASE: hostile_onchain_claim', file=sys.stderr)
        resolve(30)
        print('PHASE: hostile_payer_learns', file=sys.stderr)
        attempts = [future.result(timeout=120) for future in shards]
        print('PHASE: hostile_receiver_funds', file=sys.stderr)
        for _ in range(100):
            received = call(b, b_secret, 'WalletBalance', ln.WalletBalanceRequest,
                ln.WalletBalanceResponse, ln.WalletBalanceRequest()).confirmed_balance
            if received > 120_000:
                break
            time.sleep(0.2)
    else:
        print('PHASE: hostile_timeout', file=sys.stderr)
        rpc('generatetoaddress', [130, mining_address], wallet='fund')
        synced(attempts=600)
        resolve(60)
        print('PHASE: hostile_payer_fails', file=sys.stderr)
        attempts = [future.result(timeout=120) for future in shards]
        received = call(b, b_secret, 'WalletBalance', ln.WalletBalanceRequest,
            ln.WalletBalanceResponse, ln.WalletBalanceRequest()).confirmed_balance
    print(json.dumps({'funding_txid': txid, 'vout': point.output_index,
        'capacity_sat': views[0][0].capacity, 'settled': settle_after_close,
        'height': height, 'parts': parts,
        'spends': sorted([spend['height'], spend['preimage']] for spend in spends.values()),
        'payer': [[attempt.status, attempt.preimage == preimage] for attempt in attempts],
        'received_sat': received}))
"""


def _run(tmp_path: Path, *, settle: bool) -> dict[str, object]:
    helpers = import_module("test_lnd_payment_pinned")
    program = f"SETTLE_AFTER_CLOSE = {settle}\n" + helpers.CHANNEL_SETUP + SCENARIO
    evidence: dict[str, object] = helpers._run_two_node_sidecar(  # noqa: SLF001 - shared fixture
        tmp_path,
        program,
        prefix="hostile-close",
        deadline=480,
        profile="receiver_restart",
        funding_spent=True,
    )
    height = evidence["height"]
    assert isinstance(height, int)
    assert evidence["parts"] == [[80_000_000, height + 144], [120_000_000, height + 160]]
    return evidence


SUCCEEDED, FAILED = 1, 2  # lnrpc.HTLCAttempt.HTLCStatus


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1",
    reason="set RILLSWAP_RUN_LND=1 for pinned disposable LND",
)
def test_settling_after_a_hostile_close_and_restart_claims_every_shard(tmp_path: Path) -> None:
    """Both held shards are swept on chain with the preimage before they expire."""
    evidence = _run(tmp_path, settle=True)
    height = evidence["height"]
    assert isinstance(height, int)
    spends = evidence["spends"]
    assert isinstance(spends, list)
    assert len(spends) == 2  # one per shard
    assert all(preimage and spent < height + 144 for spent, preimage in spends)
    assert evidence["payer"] == [[SUCCEEDED, True], [SUCCEEDED, True]]
    received = evidence["received_sat"]
    assert isinstance(received, int)
    assert 120_000 < received <= 200_000  # both shards, less on-chain fees


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1",
    reason="set RILLSWAP_RUN_LND=1 for pinned disposable LND",
)
def test_without_a_settlement_the_payer_times_out_every_shard(tmp_path: Path) -> None:
    """Control: the same close without the preimage leaves only timeout spends."""
    evidence = _run(tmp_path, settle=False)
    height = evidence["height"]
    assert isinstance(height, int)
    spends = evidence["spends"]
    assert isinstance(spends, list)
    assert len(spends) == 2  # one per shard
    assert [preimage for _, preimage in spends] == [False, False]
    assert spends[0][0] > height + 144
    assert spends[1][0] > height + 160
    assert evidence["payer"] == [[FAILED, False], [FAILED, False]]
    received = evidence["received_sat"]
    assert isinstance(received, int)
    assert received < 80_000  # no shard value reached the receiver
