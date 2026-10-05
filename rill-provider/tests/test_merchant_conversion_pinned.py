"""Owned incoming accounting, original receipts and explicit completion conformance.

The initial authenticated merchant flow is the unchanged M29 diagnostic template.
Checked test-only substitutions change only this scenario's amount/provider/
destination and final evidence. Existing scenarios, assertions and artifacts are
not rewritten. This is not a production accounting projector or relay policy.
"""

# ruff: noqa: E501
# Embedded sidecar RPC statements and checked literal template markers are kept
# intact; compile tests validate generated Python without running any effects.

from __future__ import annotations

import ast
import hashlib
import os
import subprocess
import tempfile
from importlib import import_module
from pathlib import Path

import pytest

CRASH_CHILD = """
import json, os, signal, sys
from contextlib import contextmanager
from pathlib import Path
from rill_crypto import Context
from rill_cli.age_container import X25519Credentials
from rill_cli.conversion_journal import ConversionJournal, SourceAuthority
from rill_cli.reverse_conversion import ReverseExecutionConfig
from rill_cli.reverse_reconciliation import BlockHint, DestinationCustody, reconcile_conversion

stage='inputs'
try:
    value = json.loads(sys.stdin.buffer.read(65537))
    assert value['boundary'] in ('before_commit','after_commit')
    directory = Path(value['directory'])
    assert directory.stat().st_uid == os.getuid()
    authority = SourceAuthority.model_validate(value['authority'])
    custody = DestinationCustody.model_validate(value['custody'])
    configuration = value['config']
    for name in ('lnd_tls_root_path','lnd_read_macaroon_path','lnd_payment_macaroon_path','core_cookie_path'):
        configuration[name] = Path(configuration[name])
    config = ReverseExecutionConfig(**configuration)
    credentials = X25519Credentials(**value['credentials'])
    stage='open'
    journal = ConversionJournal.open(directory,Path(value['fence']),authority)
    original_transaction, original_complete = journal._transaction, journal.complete
    def terminate():
        sys.stdout.write('BOUNDARY:' + value['boundary'] + '\\n')
        sys.stdout.flush()
        os.kill(os.getpid(),signal.SIGKILL)
    @contextmanager
    def killed_transaction():
        with original_transaction() as db:
            yield db
            # Only successful completion-body exit reaches the kill hook.
            if value['boundary']=='before_commit': terminate()
        if value['boundary']=='after_commit': terminate()
    def complete(*args,**kwargs):
        journal._transaction=killed_transaction
        try: return original_complete(*args,**kwargs)
        finally: journal._transaction=original_transaction
    journal.complete=complete
    stage='native_reconciliation'
    with Context(library_path='/work/provider/tmp/native/librill_crypto.so') as crypto:
        reconcile_conversion(journal,value['operation_id'],config=config,credentials=credentials,crypto=crypto,
            funding_recovery_path=Path(value['candidate']),funding_attempt_id=value['funding_attempt_id'],
            binding_revision=value['binding_revision'],funding_block=BlockHint.model_validate(value['funding_block']),
            claim_txid=value['claim_txid'],claim_path='cooperative',custody=custody)
    sys.stdout.write('UNEXPECTED:boundary_not_reached\\n')
    sys.stdout.flush()
    os._exit(91)
except BaseException:
    # Never expose secret input, validation values, upstream errors or traceback.
    sys.stdout.write('REFUSED:'+stage+'\\n')
    sys.stdout.flush()
    os._exit(92)
"""

EXTRA = """
    import asyncio, logging, signal
    from pyrage import x25519
    from rill_core.wire.canonical import canonicalize
    from rill_crypto import Context
    from fake_relay import FakeRelay
    from rill_provider.core_tx_bytes import CoreTransactionReader
    from rill_provider.handshake_service import HandshakeService, ServicePolicy
    from rill_provider.handshake_store import HandshakePolicy
    from rill_provider.live_session_store import AuthorityDeclaration, LiveSessionStore
    from rill_provider.provider_identity import ProviderIdentity
    from rill_provider.quote_policy import QuoteSchedule
    from rill_provider.relay_client import RelayConnection
    from rill_provider.lnd_hold_invoice import LndHoldInvoices
    from rill_provider.lnd_invoice_decode import LndInvoiceDecoder
    from rill_provider.lnd_payment_send import LndPaymentSender
    from rill_provider.lnd_treasury_observation import LndTreasuryObserver
    from rill_provider.settlement_engine import EngineSettings, SettlementEngine
    from rill_cli.age_container import X25519Credentials, decrypt_verified_plaintext
    from rill_cli.conversion_journal import (
        Allocation, ConversionJournal, ConversionRequest, InventoryAccountingEligibility)
    from rill_cli.live_reverse_swap import ReverseSwapLimits
    from rill_cli.reverse_conversion import ReverseExecutionConfig, run_reserved_conversion
    from rill_cli import reverse_conversion as original_reverse
    from rill_cli.reverse_reconciliation import (
        BlockHint, DestinationCustody, collect_conversion_receipt, reconcile_conversion)
    from rill_cli import reverse_reconciliation as reconciliation_module
    logging.basicConfig(level=logging.CRITICAL)
    provider_data = None

    def claim_receipt_ready(states,transaction,minimum_depth):
        depth=transaction.get('confirmations')
        return states==[('SETTLED',)] and type(depth) is int and depth>=minimum_depth

    def inventory_snapshot(journal):
        with sqlite3.connect((journal.directory/'inventory.sqlite').as_uri()+'?mode=ro',uri=True) as inventory:
            return (inventory.execute('SELECT * FROM metadata ORDER BY id').fetchall(),
                inventory.execute('SELECT * FROM jobs ORDER BY operation_id').fetchall(),
                inventory.execute('SELECT * FROM credits ORDER BY payment_hash').fetchall(),
                inventory.execute('SELECT * FROM holds ORDER BY kind,owner,payment_hash').fetchall())

    async def crash_completion(journal,config,credentials,crypto,candidate,binding,funding_info,claim_txid,custody,data):
        before = inventory_snapshot(journal)
        generation = journal.begin_capacity_query().generation
        private_paths = (journal.directory/'recovery'/'owned_treasury_reverse_01.age',candidate,
            journal.source_fence,journal.directory.parent/'provider.age',
            config.core_cookie_path,config.lnd_tls_root_path,config.lnd_read_macaroon_path,
            config.lnd_payment_macaroon_path,data['cert_a'],data['mac_a'])
        private_before = immutable(private_paths)
        original_payments = call(b,b_secret,'ListPayments',ln.ListPaymentsRequest,ln.ListPaymentsResponse,
            ln.ListPaymentsRequest(include_incomplete=True)).SerializeToString()
        payload = dict(boundary=CRASH_BOUNDARY,directory=str(journal.directory),fence=str(journal.source_fence),
            operation_id='owned_treasury_reverse_01',authority=journal.authority.model_dump(mode='json'),
            custody=custody.model_dump(mode='json'),credentials=dict(recipient=credentials.recipient,identity=credentials.identity),
            config=dict(lnd_port=config.lnd_port,lnd_tls_root_path=str(config.lnd_tls_root_path),
                lnd_read_macaroon_path=str(config.lnd_read_macaroon_path),lnd_payment_macaroon_path=str(config.lnd_payment_macaroon_path),
                core_port=config.core_port,core_cookie_path=str(config.core_cookie_path),core_wallet=config.core_wallet),
            candidate=str(candidate),funding_attempt_id=binding['funding_attempt_id'],binding_revision=binding['binding_revision'],
            funding_block=dict(height=funding_info['blockheight'],block_hash=funding_info['blockhash']),claim_txid=claim_txid)
        encoded=canonicalize(payload)
        assert len(encoded)<=65536
        child = None
        try:
            child=await asyncio.to_thread(subprocess.run,[sys.executable,'-c',CRASH_CHILD],
                input=encoded,capture_output=True,timeout=45,check=False)
        except Exception: pass
        # Fixed messages only: timeout/CompletedProcess may retain captured data.
        assert child is not None,'owned reconciliation child unavailable'
        for phase in ('inputs','open','native_reconciliation'):
            if child.stdout==('REFUSED:'+phase+'\\n').encode():
                print('PHASE: owned_child_refused_'+phase,file=sys.stderr)
        assert child.returncode==-signal.SIGKILL,'owned reconciliation child did not reach kill boundary'
        assert child.stdout==('BOUNDARY:'+CRASH_BOUNDARY+'\\n').encode(),'unexpected owned child marker'
        assert child.stderr==b'','owned reconciliation child emitted diagnostics'
        reopened = ConversionJournal.open(journal.directory,journal.source_fence,journal.authority)
        job = reopened.status('owned_treasury_reverse_01')
        if CRASH_BOUNDARY=='before_commit':
            assert inventory_snapshot(reopened)==before
            assert job.state=='dispatched' and job.receipt is None
            assert reopened.begin_capacity_query().generation==generation
        else:
            assert job.state=='complete' and job.receipt is not None
            assert reopened.begin_capacity_query().generation==generation+1
        assert immutable(private_paths)==private_before
        final_payments = call(b,b_secret,'ListPayments',ln.ListPaymentsRequest,ln.ListPaymentsResponse,
            ln.ListPaymentsRequest(include_incomplete=True)).SerializeToString()
        assert final_payments==original_payments
        return reopened,(original_payments,private_paths,private_before)

    def synchronize():
        height = rpc('getblockcount', [])
        block = rpc('getblockhash', [height])
        until = time.monotonic() + 15
        while time.monotonic() < until:
            info = [call(node, secret, 'GetInfo', ln.GetInfoRequest, ln.GetInfoResponse,
                ln.GetInfoRequest()) for node, secret in ((a,a_secret),(b,b_secret))]
            if all(value.synced_to_chain and value.block_height == height and
                value.block_hash == block for value in info): return height, block
            time.sleep(0.1)
        raise AssertionError('owned nodes did not synchronize to exact Core tip')

    def prepare_provider(directory, network):
        rpc('createwallet', ['provider'])
        rpc('createwallet', ['merchant'])
        provider_address = rpc('getnewaddress', ['', 'bech32m'], wallet='provider')
        rpc('sendtoaddress', [provider_address, 1], wallet='fund')
        rpc('generatetoaddress', [1, mining_address], wallet='fund')
        synchronize()
        assert rpc('getwalletinfo', [], wallet='merchant')['private_keys_enabled'] is True
        crypto = Context(library_path='/work/provider/tmp/native/librill_crypto.so')
        unlock, custody = x25519.Identity.generate(), x25519.Identity.generate()
        identity = ProviderIdentity.provision(directory/'provider.age',
            recipient=str(unlock.to_public()), crypto=crypto)
        signer = ProviderIdentity.load(directory/'provider.age', custody_identity=str(unlock),
            expected_xonly_public_key=identity, crypto=crypto)
        policy = HandshakePolicy(profile='ln-to-btc/v1',
            features=frozenset({'cooperative-claim/v1'}),
            encryption_suites=frozenset({'noise-xk-secp256k1-chachapoly-sha256/v1'}),
            capabilities=frozenset({'core/v1','recovery/v1'}))
        LiveSessionStore.provision(directory/'provider.sqlite', network, identity, policy,
            AuthorityDeclaration('owned-treasury-fixture', outside_restore_domain=True,
                single_host=True), custody_recipient=str(custody.to_public()))
        cert_a = private_file(directory, 'provider.cert', Path('/work/public/a.cert').read_bytes())
        mac_a = private_file(directory, 'provider.mac', a_secret)
        read_b = bake([ln.MacaroonPermission(entity='uri', action=uri) for uri in (
            '/lnrpc.Lightning/GetInfo', '/lnrpc.Lightning/ListChannels',
            '/lnrpc.Lightning/DecodePayReq', '/routerrpc.Router/TrackPaymentV2')])
        pay_b = bake([ln.MacaroonPermission(entity='uri', action=uri) for uri in (
            '/lnrpc.Lightning/GetInfo', '/lnrpc.Lightning/DecodePayReq',
            '/lnrpc.Lightning/QueryRoutes', '/routerrpc.Router/SendToRouteV2',
            '/routerrpc.Router/TrackPaymentV2')])
        return dict(crypto=crypto, identity=identity, signer=signer, custody=custody,
            policy=policy, cert_a=cert_a, mac_a=mac_a,
            read_b=private_file(directory,'source-read.mac',read_b),
            pay_b=private_file(directory,'source-pay.mac',pay_b),
            provider_script=rpc('getaddressinfo',[provider_address],wallet='provider')['scriptPubKey'])

    def drained_channels():
        tip = synchronize()
        observed = []
        for node, secret, counterpart, initiator in ((a,a_secret,b_key,True),(b,b_secret,a_key,False)):
            channels = call(node,secret,'ListChannels',ln.ListChannelsRequest,
                ln.ListChannelsResponse,ln.ListChannelsRequest())
            assert len(channels.channels) == 1
            channel = channels.channels[0]
            assert channel.active and channel.private and channel.initiator == initiator
            assert channel.channel_point == txid + ':' + str(point.output_index)
            assert channel.capacity == 1000000 and channel.remote_pubkey == counterpart
            assert channel.chan_status_flags == 'ChanStatusDefault'
            assert len(channel.pending_htlcs) == 0 and channel.unsettled_balance == 0
            assert not channel.custom_channel_data
            assert channel.HasField('local_constraints') and channel.HasField('remote_constraints')
            peers = call(node,secret,'ListPeers',ln.ListPeersRequest,ln.ListPeersResponse,ln.ListPeersRequest())
            assert len(peers.peers) == 1 and peers.peers[0].pub_key == counterpart
            peer = peers.peers[0]
            assert (peer.flap_count,peer.last_flap_ns) == peer_anchor[counterpart]
            assert len(peer.errors) == 0
            pending = call(node,secret,'PendingChannels',ln.PendingChannelsRequest,
                ln.PendingChannelsResponse,ln.PendingChannelsRequest())
            assert all(len(getattr(pending,name)) == 0 for name in (
                'pending_open_channels','pending_closing_channels',
                'pending_force_closing_channels','waiting_close_channels'))
            observed.append(channel)
        assert observed[1].local_balance == 200000
        assert observed[1].total_satoshis_sent == 0
        assert synchronize() == tip
        # Exclude elapsed uptime/lifetime and other read-time statistics.
        return tip, tuple((channel.channel_point,channel.chan_id,channel.local_balance,
            channel.remote_balance,channel.total_satoshis_sent,channel.total_satoshis_received,
            channel.commitment_type,channel.commit_fee,channel.fee_per_kw,
            channel.local_constraints.SerializeToString(),channel.remote_constraints.SerializeToString())
            for channel in observed)

    def reserve_known_incoming(directory, authority, credit, data):
        print('PHASE: incoming_only_accounting',file=sys.stderr)
        (directory/'inventory').mkdir(mode=0o700)
        journal = ConversionJournal.provision(directory/'inventory', directory/'inventory-owner.json', authority)
        request = ConversionRequest(operation_id='owned_treasury_reverse_01',
            allocations=(Allocation(payment_hash=credit.payment_hash, amount_msat=105000000),),
            requested_payout_sat=100000, minimum_output_sat=96000,
            max_source_debit_msat=105000000, max_fee_msat=9000000,
            max_routing_fee_msat=100000, confirmation_blocks=3, expires_at=int(time.time())+600)
        query = journal.begin_capacity_query()
        before = drained_channels()
        observer = LndTreasuryObserver(host='127.0.0.1',port=10010,
            tls_certificate_path=Path('/work/public/b.cert'),read_macaroon_path=data['read_b'],
            network=authority.network,expected_node_pubkey=b_key)
        accounting = observer.observe_accounting()
        after = drained_channels()
        assert before == after
        assert accounting.channel_count == accounting.classified_channel_count == 1
        assert accounting.coverage_complete is True
        assert accounting.classified_pending_incoming_floor_msat == 0
        assert accounting.classified_pending_outgoing_floor_msat == 0
        assert accounting.classified_local_commitment_floor_msat == 200000000
        assert accounting.context.observed_node_pubkey == b_key
        assert (accounting.context.before_tip.height, accounting.context.before_tip.block_hash) == before[0]
        assert (accounting.context.after_tip.height, accounting.context.after_tip.block_hash) == before[0]
        eligibility = InventoryAccountingEligibility(source_node=b_key,network=authority.network,
            query=query,observed_at=int(time.time()),
            accounting_net_msat=max(0,accounting.classified_local_commitment_floor_msat-
                accounting.classified_local_reserve_msat),coverage_complete=True,commitments_known=True)
        reservation = journal.reserve_accounting_conversion(request,credits=(credit,),eligibility=eligibility)
        assert reservation.job.state == 'reserved'
        print('PHASE: accounting_inventory_reserved',file=sys.stderr)
        return journal,reservation

    async def funded_reverse(directory, authority, credit, data):
        journal,reservation = reserve_known_incoming(directory,authority,credit,data)
        crypto = data['crypto']
        unlock = x25519.Identity.generate()
        credentials = X25519Credentials(str(unlock.to_public()),str(unlock))
        config = ReverseExecutionConfig(10010,Path('/work/public/b.cert'),data['read_b'],data['pay_b'],
            18443,Path('/work/public/core.cookie'),'merchant')
        relay = FakeRelay()
        url = await relay.start()
        stop, mining_stop = asyncio.Event(),asyncio.Event()
        def mine():
            rpc('generatetoaddress',[1,mining_address],wallet='fund')
            synchronize()
        async def miner():
            for _ in range(180):
                await asyncio.sleep(0.5)
                if mining_stop.is_set(): return
                await asyncio.to_thread(mine)
            raise AssertionError('owned mining window exhausted')
        with LiveSessionStore.acquire(directory/'provider.sqlite',authority.network,data['identity'],
            data['policy'],crypto=crypto,custody_identity=str(data['custody']),public_keys=crypto) as store:
            chain = CoreTransactionReader(port=18443,cookie_path=Path('/work/public/core.cookie'),
                network=authority.network,wallet='provider')
            held = LndHoldInvoices(host='127.0.0.1',port=10009,tls_certificate_path=data['cert_a'],
                macaroon_path=data['mac_a'],network=authority.network)
            decoder = LndInvoiceDecoder(host='127.0.0.1',port=10009,tls_certificate_path=data['cert_a'],
                macaroon_path=data['mac_a'],network=authority.network)
            lightning = LndPaymentSender(host='127.0.0.1',port=10009,tls_certificate_path=data['cert_a'],
                macaroon_path=data['mac_a'],network=authority.network)
            engine = SettlementEngine(store,chain,lightning,crypto,
                EngineSettings(allow_regtest_fixed_fee=True),hold_invoices=held)
            policy = ServicePolicy(network=authority.network,profiles=('ln-to-btc/v1',),profile='ln-to-btc/v1',
                amount_bands=((1000,1000000),),base_fee_sat=50,proportional_millionths=1000,
                slot='owned-treasury',relay_urls=(url,),provider_destination_script=data['provider_script'],
                quote=QuoteSchedule(max_funding_fee_sat=500,max_claim_fee_sat=400,
                    max_refund_fee_sat=600,max_refund_delay_blocks=288))
            service = HandshakeService(store,data['signer'],crypto,policy,chain_tip=chain.tip_height,
                invoice_decoder=decoder.decode,settlement=engine,hold_invoices=held)
            runner = asyncio.create_task(service.run(stop,tick_seconds=0.2))
            mining = asyncio.create_task(miner())
            try:
                print('PHASE: original_reserved_reverse',file=sys.stderr)
                native_runner = original_reverse.run_reverse_swap
                stage = ['starting']
                cooperative_events = []
                def trace(message):
                    # Print only fixed progress categories, never SDK payloads.
                    cooperation = {
                        'cooperative claim window unavailable; claiming unilaterally':'window_unavailable',
                        'cooperative disclosure not recorded; claiming unilaterally':'disclosure_unrecorded',
                        "cooperative claim proposed; waiting for the provider's signature":'proposal_sent',
                        'no cooperative signature in time; claiming unilaterally':'signature_timeout',
                        'provider declined cooperation; claiming unilaterally':'provider_declined',
                        'provider cooperative signature invalid; claiming unilaterally':'signature_invalid',
                    }
                    if message in cooperation:
                        cooperative_events.append(cooperation[message])
                        print('PHASE: original_reverse_cooperative_'+cooperation[message],file=sys.stderr)
                        return
                    if message.startswith('cooperative claim '):
                        cooperative_events.append('claim_submitted')
                        print('PHASE: original_reverse_cooperative_claim_submitted',file=sys.stderr)
                        return
                    for prefix,label in (('session ','session'),('terms: ','terms'),
                        ('recovery file written','checkpoint'),('hold payment observed','payment'),
                        ('funding ','funding'),('claim ','claim')):
                        if message.startswith(prefix):
                            stage[0]=label
                            print('PHASE: original_reverse_'+label,file=sys.stderr)
                            return
                async def traced_runner(*args,**kwargs):
                    kwargs['report']=trace
                    try: return await native_runner(*args,**kwargs)
                    except Exception:
                        current=journal.status(reservation.job.request.operation_id).state
                        print('PHASE: original_reverse_failed_'+stage[0]+'_'+current,file=sys.stderr)
                        raise
                original_reverse.run_reverse_swap=traced_runner
                async with RelayConnection(url) as connection:
                    try:
                        outcome = await run_reserved_conversion(journal,reservation,connection,config=config,
                            limits=ReverseSwapLimits(max_success_fee_sat=1000,min_claim_fee_reserve_sat=500,
                                max_claim_fee_sat=5000,min_refund_delay_blocks=72,
                                max_incoming_htlc_delay_blocks=432,max_routing_fee_sat=100,claim_fee_rate_sat_vb=2),
                            credentials=credentials,crypto=crypto,timeout=30,settle_timeout=150)
                    finally: original_reverse.run_reverse_swap=native_runner
                async with asyncio.timeout(30):
                    while True:
                        states=store._connection.execute('SELECT state FROM swaps').fetchall()
                        transaction=await asyncio.to_thread(rpc,'gettransaction',[outcome.claim_txid],wallet='merchant')
                        if claim_receipt_ready(states,transaction,reservation.job.request.confirmation_blocks): break
                        await asyncio.sleep(0.2)
                mining_stop.set()
                await mining
                await asyncio.to_thread(synchronize)
                print('PHASE: original_reverse_receipt',file=sys.stderr)
                candidate_path = journal.directory/'recovery'/(reservation.job.request.operation_id+'.age.funded')
                plaintext = decrypt_verified_plaintext(candidate_path.read_bytes(),authority.network,
                    credentials=credentials,crypto=crypto)
                records = json.loads(plaintext)['funding_history']
                assert len(records) == 1
                binding = records[0]['binding']
                assert binding['funding_txid'] == outcome.funding_txid
                before_receipt = journal.begin_capacity_query()
                funding_info = await asyncio.to_thread(rpc,'gettransaction',[outcome.funding_txid],wallet='provider')
                custody = DestinationCustody(network=authority.network,script=authority.treasury_script,
                    core_wallet='merchant',destination_keys_controlled=True)
                targets = (
                    (reconciliation_module.CoreTransactionReader,'observe_block_transaction','block_bytes'),
                    (reconciliation_module,'check_funding_binding_transaction','funding_binding'),
                    (reconciliation_module.WalletRpc,'observe_historical_wallet_output','destination_history'),
                    (reconciliation_module,'validate_cooperative_claim','cooperative_validation'),
                    (reconciliation_module.LndTreasuryObserver,'observe_completed_payment','source_payment'),
                    (reconciliation_module.CoreTransactionReader,'observe_source','chain_sample'),
                    (reconciliation_module,'_collect','receipt_join'),
                )
                originals = []
                raised_phase=['receipt_join']
                def diagnostic(original,label):
                    def observed(*args,**kwargs):
                        print('PHASE: receipt_'+label+'_enter',file=sys.stderr)
                        try: result=original(*args,**kwargs)
                        except Exception as error:
                            if label!='receipt_join': raised_phase[0]=label
                            if label=='receipt_join':
                                reasons={
                                    'source and contract chain observations contradict':'chain_correspondence',
                                    'historical claim depth below approval':'claim_depth',
                                    'conversion observations changed during acquisition':'generation_or_clock',
                                    'historical conversion acquisition expired':'acquisition_expired',
                                }
                                for message,tag in reasons.items():
                                    if error.args==(message,):
                                        print('PHASE: receipt_join_'+tag,file=sys.stderr)
                                        raise
                            event=cooperative_events[-1] if cooperative_events else 'no_cooperative_event'
                            print('PHASE: receipt_'+raised_phase[0]+'_raised_after_'+event,file=sys.stderr)
                            raise
                        print('PHASE: receipt_'+label+'_returned',file=sys.stderr)
                        return result
                    return observed
                try:
                    for owner,name,label in targets:
                        original=getattr(owner,name)
                        originals.append((owner,name,original))
                        setattr(owner,name,diagnostic(original,label))
                    receipt = await asyncio.to_thread(collect_conversion_receipt,journal,
                        reservation.job.request.operation_id,config=config,credentials=credentials,crypto=crypto,
                        funding_recovery_path=candidate_path,funding_attempt_id=binding['funding_attempt_id'],
                        binding_revision=binding['binding_revision'],
                        funding_block=BlockHint(height=funding_info['blockheight'],block_hash=funding_info['blockhash']),
                        claim_txid=outcome.claim_txid,claim_path='cooperative',custody=custody)
                finally:
                    for owner,name,original in originals: setattr(owner,name,original)
                job = journal.status(reservation.job.request.operation_id)
                assert job.state == 'dispatched' and job.receipt is None
                assert receipt.payment_hash == job.prepared.payment_hash
                assert receipt.destination_script == authority.treasury_script
                assert receipt.destination_txid == outcome.claim_txid
                assert receipt.destination_value_sat >= job.prepared.minimum_net_output_sat
                assert receipt.confirmation_blocks >= 3
                after_receipt = journal.begin_capacity_query()
                assert (after_receipt.journal_id,after_receipt.generation) == (
                    before_receipt.journal_id,before_receipt.generation)
                with sqlite3.connect((journal.directory/'inventory.sqlite').as_uri()+'?mode=ro',uri=True) as inventory:
                    assert inventory.execute('SELECT kind,owner,payment_hash,amount_msat FROM holds').fetchall() == [
                        ('conversion',reservation.job.request.operation_id,credit.payment_hash,105000000)]
                    assert inventory.execute('SELECT payment_hash,consumed_msat FROM credits').fetchall() == [
                        (credit.payment_hash,0)]
                original_invoices = call(b,b_secret,'ListInvoices',ln.ListInvoiceRequest,ln.ListInvoiceResponse,
                    ln.ListInvoiceRequest())
                assert len(original_invoices.invoices)==1 and original_invoices.invoices[0].settled
                assert original_invoices.invoices[0].amt_paid_msat==credit.amount_msat
                paid = call(b,b_secret,'ListPayments',ln.ListPaymentsRequest,ln.ListPaymentsResponse,
                    ln.ListPaymentsRequest(include_incomplete=True))
                assert len(paid.payments)==1
                payment=paid.payments[0]
                assert payment.status==ln.Payment.SUCCEEDED and payment.payment_hash==receipt.payment_hash
                assert len(payment.htlcs)==1 and payment.htlcs[0].status==ln.HTLCAttempt.SUCCEEDED
                assert payment.value_msat==receipt.amount_msat and payment.fee_msat==receipt.routing_fee_msat
                assert payment.htlcs[0].route.first_hop_amount_msat==receipt.amount_msat+receipt.routing_fee_msat
                if COMPLETION_SCENARIO:
                    print('PHASE: explicit_verified_completion',file=sys.stderr)
                    crash_snapshot = None
                    if CRASH_BOUNDARY is not None:
                        print('PHASE: completion_process_death_'+CRASH_BOUNDARY,file=sys.stderr)
                        journal,crash_snapshot=await crash_completion(journal,config,credentials,crypto,candidate_path,binding,
                            funding_info,outcome.claim_txid,custody,data)
                        assert store._connection.execute('SELECT state FROM swaps').fetchall()==[('SETTLED',)]
                    reopened_before = inventory_snapshot(journal)
                    after_kill_factories = {}
                    def no_acquisition(*args,**kwargs):
                        raise AssertionError('terminal status must not acquire or execute')
                    if CRASH_BOUNDARY=='after_commit':
                        after_kill_factories={name:getattr(reconciliation_module,name) for name in (
                            'CoreTransactionReader','WalletRpc','LndTreasuryObserver','collect_conversion_receipt')}
                        for name in after_kill_factories: setattr(reconciliation_module,name,no_acquisition)
                    try:
                        completed = await asyncio.to_thread(reconcile_conversion,journal,
                            reservation.job.request.operation_id,config=config,credentials=credentials,crypto=crypto,
                            funding_recovery_path=candidate_path,funding_attempt_id=binding['funding_attempt_id'],
                            binding_revision=binding['binding_revision'],
                            funding_block=BlockHint(height=funding_info['blockheight'],block_hash=funding_info['blockhash']),
                            claim_txid=outcome.claim_txid,claim_path='cooperative',custody=custody)
                    finally:
                        for name,factory in after_kill_factories.items(): setattr(reconciliation_module,name,factory)
                    if CRASH_BOUNDARY=='after_commit': assert inventory_snapshot(journal)==reopened_before
                    assert completed.state=='complete' and completed.receipt==receipt
                    assert journal.begin_capacity_query().generation==after_receipt.generation+1
                    with sqlite3.connect((journal.directory/'inventory.sqlite').as_uri()+'?mode=ro',uri=True) as inventory:
                        assert inventory.execute('SELECT * FROM holds').fetchall()==[]
                        stored_document,consumed=inventory.execute('SELECT credit,consumed_msat FROM credits').fetchone()
                        stored_credit=json.loads(stored_document)
                        assert stored_credit==credit.model_dump(mode='json')
                        assert consumed==receipt.amount_msat+receipt.routing_fee_msat
                        assert stored_credit['amount_msat']-consumed==200000000-receipt.amount_msat-receipt.routing_fee_msat
                    before_terminal=journal.begin_capacity_query()
                    persisted_before_terminal=inventory_snapshot(journal)
                    factories={name:getattr(reconciliation_module,name) for name in (
                        'CoreTransactionReader','WalletRpc','LndTreasuryObserver','collect_conversion_receipt')}
                    for name in factories: setattr(reconciliation_module,name,no_acquisition)
                    try:
                        terminal = reconcile_conversion(journal,reservation.job.request.operation_id,
                            config=config,credentials=credentials,crypto=crypto,funding_recovery_path=candidate_path,
                            funding_attempt_id=binding['funding_attempt_id'],binding_revision=binding['binding_revision'],
                            funding_block=BlockHint(height=funding_info['blockheight'],block_hash=funding_info['blockhash']),
                            claim_txid=outcome.claim_txid,claim_path='cooperative',custody=custody)
                        assert terminal==completed
                    finally:
                        for name,factory in factories.items(): setattr(reconciliation_module,name,factory)
                    assert journal.begin_capacity_query().generation==before_terminal.generation
                    assert inventory_snapshot(journal)==persisted_before_terminal
                    final_paid=call(b,b_secret,'ListPayments',ln.ListPaymentsRequest,ln.ListPaymentsResponse,
                        ln.ListPaymentsRequest(include_incomplete=True))
                    assert len(final_paid.payments)==1 and len(final_paid.payments[0].htlcs)==1
                    if crash_snapshot is not None:
                        original_payments,private_paths,private_before=crash_snapshot
                        assert final_paid.SerializeToString()==original_payments
                        assert immutable(private_paths)==private_before
                assert store._connection.execute('SELECT state FROM swaps').fetchall()==[('SETTLED',)]
                return dict(original_reverse_receipt=True,source_debit_msat=receipt.amount_msat+receipt.routing_fee_msat,
                    destination_value_sat=receipt.destination_value_sat,claim_depth=receipt.confirmation_blocks,
                    original_source_attempts=1,inventory_hold_retained=not COMPLETION_SCENARIO,
                    verified_completion=COMPLETION_SCENARIO,accounting_admission=True,
                    process_death_boundary=CRASH_BOUNDARY)
            finally:
                mining_stop.set()
                try: await mining
                finally:
                    stop.set()
                    try: await runner
                    finally: await relay.stop()

    peer_anchor = {}
    for node,secret,counterpart in ((a,a_secret,b_key),(b,b_secret,a_key)):
        peers=call(node,secret,'ListPeers',ln.ListPeersRequest,ln.ListPeersResponse,ln.ListPeersRequest())
        assert len(peers.peers)==1 and peers.peers[0].pub_key==counterpart
        peer=peers.peers[0]
        assert 0 <= peer.flap_count <= 1
        peer_anchor[counterpart]=(peer.flap_count,peer.last_flap_ns)
"""


def _program(
    original: str | None = None, *, completion: bool = False, crash_boundary: str | None = None
) -> str:
    fixture = import_module("test_merchant_source_pinned")
    setup = import_module("test_lnd_payment_pinned").CHANNEL_SETUP
    if original is None:
        original = fixture.FUNDED_MERCHANT_PROOF
    assert isinstance(setup, str)
    assert isinstance(original, str)
    assert original.startswith(setup)
    body = original[len(setup) :]
    for statement in (
        "'orderRef': 'owned-funded-proof', 'amountMsat': '1000000',",
        "assert terms['amountMsat'] == '1000000' and terms['network'] == 'regtest'",
        "assert decoded.num_msat == 1000000 and decoded.destination == b_key",
        "amt_msat=1000000, final_cltv_delta=decoded.cltv_expiry,",
        "and routes.routes[0].total_amt_msat == 1000000): break",
        "assert completed.value_msat == 1000000 and completed.fee_msat == 0",
        "assert successful[0].route.first_hop_amount_msat == 1000000",
        "assert credit.amount_msat == 1000000",
    ):
        assert body.count(statement) == 1, "merchant amount statement changed"
        body = body.replace(statement, statement.replace("1000000", "200000000"))
    assert "1000000" not in body, "unexpected merchant amount context"
    namespace = "deployment_namespace='merchant-source-proof/1'"
    assert body.count(namespace) == 1
    body = body.replace(namespace, "deployment_namespace='owned-merchant-conversion/1'")
    marker = "                address = rpc('getnewaddress', ['', 'bech32m'], wallet='fund')"
    assert body.count(marker) == 1
    body = body.replace(
        marker,
        "                provider_data = prepare_provider(directory,network)\n"
        + marker.replace("wallet='fund'", "wallet='merchant'"),
    )
    marker = "owned = rpc('getaddressinfo', [address], wallet='fund')"
    assert body.count(marker) == 1
    body = body.replace(marker, marker.replace("wallet='fund'", "wallet='merchant'"))
    assert body.count("provider_identity=a_key[2:]") == 1
    body = body.replace(
        "provider_identity=a_key[2:]", "provider_identity=provider_data['identity']"
    )
    output = """                print(json.dumps({'funding_txid': txid, 'vout': point.output_index,
                    'capacity_sat': views[0][0].capacity, 'confirmations': output['confirmations'],
                    'merchant_source_provenance': True, 'agreed_amount_msat': credit.amount_msat,
                    'single_ordinary_invoice': True, 'single_payer_attempt': True,
                    'merchant_history_unchanged': True, 'private_inputs_unchanged': True}))
"""
    assert body.count(output + "        finally:") == 1, "merchant evidence/cleanup span changed"
    body = body.replace(
        output,
        """
                converted = asyncio.run(funded_reverse(directory,authority,credit,provider_data))
                assert logical(Path(config['ledgerPath'])) == before_history
                assert immutable(inputs) == before_inputs
                print(json.dumps(dict(funding_txid=txid,vout=point.output_index,
                    capacity_sat=views[0][0].capacity,confirmations=output['confirmations'],
                    merchant_source_provenance=True,agreed_amount_msat=credit.amount_msat,
                    single_ordinary_invoice=True,merchant_history_unchanged=True,
                    private_inputs_unchanged=True,**converted)))
""",
    )
    marker = "            finally: child.stdout.close(); child.stderr.close()"
    assert body.count(marker) == 1
    body = body.replace(
        marker,
        "            finally:\n                try: child.stdout.close(); child.stderr.close()\n                finally:\n                    if provider_data is not None: provider_data['crypto'].close()",
    )
    assert crash_boundary in (None, "before_commit", "after_commit")
    assert crash_boundary is None or completion
    child_program = CRASH_CHILD if crash_boundary is not None else ""
    controls = (
        f"\n    COMPLETION_SCENARIO = {completion!r}\n"
        f"    CRASH_BOUNDARY = {crash_boundary!r}\n    CRASH_CHILD = {child_program!r}\n"
    )
    return setup + controls + EXTRA + body


def test_combined_funded_program_compiles_and_preserves_original_template() -> None:
    original = import_module("test_merchant_source_pinned").FUNDED_MERCHANT_PROOF
    assert "'amountMsat': '1000000'" in original
    program = _program()
    assert "'amountMsat': '200000000'" in program
    assert "collect_conversion_receipt" in program
    assert "journal.complete" not in program
    compile(program, "<owned-merchant-conversion>", "exec")
    completed = _program(completion=True)
    assert "COMPLETION_SCENARIO = True" in completed
    compile(completed, "<owned-merchant-completion>", "exec")
    compile(CRASH_CHILD, "<owned-completion-child>", "exec")
    for boundary in ("before_commit", "after_commit"):
        compile(
            _program(completion=True, crash_boundary=boundary),
            "<owned-completion-process-death>",
            "exec",
        )


@pytest.mark.parametrize("fault", ["inserted_statement", "same_count_wrong_context"])
def test_template_drift_refuses_before_any_effects(fault: str) -> None:
    original = import_module("test_merchant_source_pinned").FUNDED_MERCHANT_PROOF
    if fault == "inserted_statement":
        original = original.replace(
            "'private_inputs_unchanged': True}))\n        finally:",
            "'private_inputs_unchanged': True}))\n                assert False\n        finally:",
        )
    else:
        original = original.replace(
            "assert decoded.num_msat == 1000000 and decoded.destination == b_key",
            "assert unrelated_numeric_context == 1000000",
        )
    with pytest.raises(
        AssertionError, match=r"merchant (amount statement|evidence/cleanup span) changed"
    ):
        _program(original)


@pytest.mark.parametrize(
    ("states", "transaction", "expected"),
    [
        ([("SETTLED",)], {"confirmations": 3}, True),
        ([("SETTLED",)], {"confirmations": 4}, True),
        ([("SETTLED",)], {"confirmations": 2}, False),
        ([("SETTLED",)], {"confirmations": 0}, False),
        ([("SETTLED",)], {"confirmations": -1}, False),
        ([("SETTLED",)], {"confirmations": True}, False),
        ([("SETTLED",)], {"confirmations": "3"}, False),
        ([("SETTLED",)], {"confirmations": 3.0}, False),
        ([("SETTLED",)], {}, False),
        ([("FUNDED",)], {"confirmations": 3}, False),
        ([], {"confirmations": 3}, False),
        ([("SETTLED",), ("SETTLED",)], {"confirmations": 3}, False),
    ],
)
def test_actual_fixture_readiness_requires_settlement_and_strict_original_depth(
    states: list[tuple[str]], transaction: dict[str, object], *, expected: bool
) -> None:
    functions: list[ast.stmt] = [
        node
        for node in ast.walk(ast.parse(_program()))
        if isinstance(node, ast.FunctionDef) and node.name == "claim_receipt_ready"
    ]
    assert len(functions) == 1
    # Execute only the actual effect-free predicate, never the surrounding RPC
    # program. This protects the readiness contract rather than restating it.
    namespace: dict[str, object] = {}
    exec(  # noqa: S102 - fixed test-owned function AST
        compile(ast.Module(body=functions, type_ignores=[]), "<claim-readiness>", "exec"), namespace
    )
    ready = namespace["claim_receipt_ready"]
    assert callable(ready)
    assert ready(states, transaction, 3) is expected


def test_combined_profile_preserves_proof_mounts_and_refuses_missing_inputs() -> None:
    helpers = import_module("test_lnd_payment_pinned")
    mounts = helpers._merchant_proof_mounts  # noqa: SLF001 - test-only metadata admission
    with pytest.raises(ValueError, match="explicit bundle and TLS"):
        mounts("merchant_conversion", None, None)
    with tempfile.TemporaryDirectory(
        prefix="conversion-mounts-", dir=helpers.ROOT.parent / "tmp"
    ) as root:
        directory = Path(root)
        directory.chmod(0o700)
        for name in ("merchant.cert", "merchant.key"):
            path = directory / name
            path.write_bytes(b"metadata-only-test-not-a-certificate")
            path.chmod(0o600)
        bundle = directory / "merchant.js"
        assert mounts("merchant_conversion", bundle, directory) == mounts(
            "merchant_proof", bundle, directory
        )
        (directory / "merchant.key").chmod(0o644)
        with pytest.raises(ValueError, match="private bounded"):
            mounts("merchant_conversion", bundle, directory)


@pytest.mark.lnd
@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1" or os.environ.get("RILLSWAP_RUN_BUN_MERCHANT") != "1",
    reason="explicit owned merchant/native treasury conformance opt-ins",
)
def test_pinned_merchant_source_to_original_owned_btc_receipt(tmp_path: Path) -> None:
    evidence = _funded_evidence(tmp_path, completion=False)
    assert evidence["inventory_hold_retained"] is True
    assert evidence["verified_completion"] is False


@pytest.mark.lnd
@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1" or os.environ.get("RILLSWAP_RUN_BUN_MERCHANT") != "1",
    reason="explicit owned merchant/native completion conformance opt-ins",
)
def test_pinned_explicit_verified_merchant_conversion_completion(tmp_path: Path) -> None:
    evidence = _funded_evidence(tmp_path, completion=True)
    assert evidence["inventory_hold_retained"] is False
    assert evidence["verified_completion"] is True


@pytest.mark.lnd
@pytest.mark.native_crypto
@pytest.mark.parametrize("boundary", ["before_commit", "after_commit"])
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1" or os.environ.get("RILLSWAP_RUN_BUN_MERCHANT") != "1",
    reason="explicit owned process-death conformance opt-ins",
)
def test_pinned_verified_completion_process_death(tmp_path: Path, boundary: str) -> None:
    evidence = _funded_evidence(tmp_path, completion=True, crash_boundary=boundary)
    assert evidence["verified_completion"] is True
    assert evidence["process_death_boundary"] == boundary


def _funded_evidence(
    tmp_path: Path, *, completion: bool, crash_boundary: str | None = None
) -> dict[str, object]:
    fixture = import_module("test_merchant_source_pinned")
    helpers = import_module("test_lnd_payment_pinned")
    tls_helpers = import_module("test_lnd_payment_tls")
    root = helpers.ROOT.parent
    assert (helpers.ROOT / "tmp/native/librill_crypto.so").is_file()
    bun = root / "tmp/toolchains/bun-v1.3.11/bun"
    assert hashlib.sha256(bun.read_bytes()).hexdigest() == fixture.BUN_SHA256
    revision = subprocess.run(  # noqa: S603 - checksum verified owned executable
        [str(bun), "--revision"], capture_output=True, text=True, check=True, timeout=5
    )
    assert revision.stdout.strip() == fixture.BUN_REVISION
    with tempfile.TemporaryDirectory(prefix="merchant-conversion-", dir=root / "tmp") as work:
        directory = Path(work)
        directory.chmod(0o700)
        tls = directory / "tls"
        tls.mkdir(mode=0o700)
        cert, _key = tls_helpers._certificate(tls)  # noqa: SLF001 - existing owned certificate fixture
        cert.rename(tls / "merchant.cert")
        (tls / "local.key").rename(tls / "merchant.key")
        for path in tls.iterdir():
            path.chmod(0o600)
        bundle = directory / "merchant.js"
        built = subprocess.run(  # noqa: S603 - checksum verified compiler, isolated bundle
            [
                str(bun),
                "build",
                "scripts/regtest-merchant.ts",
                "--target",
                "bun",
                "--outfile",
                str(bundle),
            ],
            cwd=root / "rill-payments",
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert built.returncode == 0, "owned merchant compilation refused"
        evidence: dict[str, object] = helpers._run_two_node_sidecar(  # noqa: SLF001 - additive isolated fixture profile
            tmp_path,
            _program(completion=completion, crash_boundary=crash_boundary),
            prefix="merchant-crash"
            if crash_boundary is not None
            else "merchant-completion"
            if completion
            else "merchant-conversion",
            deadline=420,
            profile="merchant_conversion",
            merchant_bun_bundle=bundle,
            merchant_proof_tls_directory=tls,
        )
    assert evidence["agreed_amount_msat"] == 200000000
    assert evidence["original_source_attempts"] == 1
    depth = evidence["claim_depth"]
    assert isinstance(depth, int)
    assert depth >= 3
    for name in (
        "original_reverse_receipt",
        "merchant_source_provenance",
        "merchant_history_unchanged",
        "private_inputs_unchanged",
        "accounting_admission",
    ):
        assert evidence[name] is True
    return evidence
