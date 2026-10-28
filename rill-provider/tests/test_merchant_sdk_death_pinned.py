"""One original SDK death boundary, explicit original-key regtest recovery only.

No runtime controller, authority restoration, automatic retry or production gate
is implemented. The existing funded fixture retains every older scenario.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from importlib import import_module
from pathlib import Path
from typing import Any

import pytest

# Embedded programs are compiled and structurally checked by offline tests.
# ruff: noqa: E501

SDK_CHILD = r"""
import asyncio, json, logging, os, sys, threading, time
from pathlib import Path
from rill_crypto import Context
from rill_cli.age_container import X25519Credentials
from rill_cli.conversion_journal import (
    Allocation, ConversionJournal, ConversionRequest, InventoryAccountingEligibility,
    SourceAuthority, SourceCredit)
from rill_cli.live_reverse_swap import ReverseSwapLimits
from rill_cli.reverse_conversion import ReverseExecutionConfig, run_reserved_conversion
from rill_cli import reverse_conversion, live_reverse_swap
from rill_provider.lnd_treasury_observation import LndTreasuryObserver
from rill_provider.relay_client import RelayConnection

logging.basicConfig(level=logging.CRITICAL)
phase='inputs'
try:
    payload=sys.stdin.buffer.readline(65538)
    assert len(payload)<=65536 and payload.endswith(b'\n')
    value=json.loads(payload)
    authority=SourceAuthority.model_validate(value['authority'])
    credit=SourceCredit.model_validate(value['credit'])
    credentials=X25519Credentials(**value['credentials'])
    directory=Path(value['directory'])
    assert directory.is_absolute() and directory.stat().st_uid==os.getuid()
    configuration=value['config']
    for name in ('lnd_tls_root_path','lnd_read_macaroon_path','lnd_payment_macaroon_path','core_cookie_path'):
        configuration[name]=Path(configuration[name])
    config=ReverseExecutionConfig(**configuration)
    phase='original_reservation'
    # Explicit fresh owned fixture provisioning, never missing-marker recovery.
    (directory/'inventory').mkdir(mode=0o700)
    journal=ConversionJournal.provision(directory/'inventory',directory/'inventory-owner.json',authority)
    request=ConversionRequest(operation_id='owned_treasury_reverse_01',
        allocations=(Allocation(payment_hash=credit.payment_hash,amount_msat=105000000),),
        requested_payout_sat=100000,minimum_output_sat=96000,max_source_debit_msat=105000000,
        max_fee_msat=9000000,max_routing_fee_msat=100000,confirmation_blocks=3,expires_at=int(time.time())+600)
    query=journal.begin_capacity_query()
    phase='accounting'
    observer=LndTreasuryObserver(host='127.0.0.1',port=config.lnd_port,
        tls_certificate_path=config.lnd_tls_root_path,read_macaroon_path=config.lnd_read_macaroon_path,
        network=authority.network,expected_node_pubkey=authority.source_node)
    accounting=observer.observe_accounting()
    assert accounting.channel_count==accounting.classified_channel_count==1
    assert accounting.coverage_complete is True
    assert accounting.classified_pending_incoming_floor_msat==0
    assert accounting.classified_pending_outgoing_floor_msat==0
    assert accounting.classified_local_commitment_floor_msat==200000000
    assert accounting.context.observed_node_pubkey==authority.source_node
    assert accounting.context.before_tip==accounting.context.after_tip
    assert [accounting.context.before_tip.height,accounting.context.before_tip.block_hash]==value['accounting_tip']
    eligibility=InventoryAccountingEligibility(source_node=authority.source_node,network=authority.network,
        query=query,observed_at=int(time.time()),
        accounting_net_msat=max(0,accounting.classified_local_commitment_floor_msat-accounting.classified_local_reserve_msat),
        coverage_complete=True,commitments_known=True)
    phase='reservation_write'
    reservation=journal.reserve_accounting_conversion(request,credits=(credit,),eligibility=eligibility)
    assert reservation.job.state=='reserved'
    print('RESERVED',flush=True)
    phase='original_sdk'
    original=reverse_conversion.run_reverse_swap
    calls=[]
    def no_signer(*args,**kwargs):
        print('SIGNER_TRIPWIRE',flush=True)
        raise AssertionError('original SDK must not acquire its claim signer')
    live_reverse_swap._claim_signer=no_signer
    async def captured(*args,**kwargs):
        calls.append(True)
        assert len(calls)==1
        owner_capture=kwargs['funding_inclusion_observer']
        def barrier(binding,terms,deadline):
            print('CAPTURE_READY',flush=True)
            assert sys.stdin.buffer.read(1)==b'1'
            owner_capture(binding,terms,deadline)
            print('FUNDING_ACK',flush=True)
            # Only the parent-owned kill terminates this test boundary. Never
            # return success into signing, even if stdin closes unexpectedly.
            threading.Event().wait()
        kwargs['funding_inclusion_observer']=barrier
        return await original(*args,**kwargs)
    reverse_conversion.run_reverse_swap=captured
    async def execute(crypto):
        async with RelayConnection(value['relay_url']) as connection:
            await run_reserved_conversion(journal,reservation,connection,config=config,
                limits=ReverseSwapLimits(max_success_fee_sat=1000,min_claim_fee_reserve_sat=0,
                    max_claim_fee_sat=5000,min_refund_delay_blocks=72,
                    max_incoming_htlc_delay_blocks=432,max_routing_fee_sat=100,claim_fee_rate_sat_vb=2),
                credentials=credentials,crypto=crypto,timeout=30,settle_timeout=150,
                retain_funding_inclusion=True)
    with Context(library_path='/work/provider/tmp/native/librill_crypto.so') as crypto:
        asyncio.run(execute(crypto))
    raise AssertionError('original SDK unexpectedly returned')
except Exception:
    print('PHASE: sdk_child_refused_'+phase,file=sys.stderr,flush=True)
    sys.exit(2)
"""

SDK_DEATH_RECOVERY = r"""
    async def funded_reverse(directory,authority,credit,data):
        import dataclasses, hashlib
        from rill_core.recovery.inspection import inspect_recovery_selected_funding_context, inspect_recovery_successor
        from rill_core.settlement import FundingOutput, UnilateralAuthorization, validate_unilateral_spend
        from rill_cli.conversion_journal import _read_private
        from rill_cli.claim_plan import verify_encrypted_claim_plan

        crypto=data['crypto']
        unlock=x25519.Identity.generate()
        credentials=X25519Credentials(str(unlock.to_public()),str(unlock))
        config=ReverseExecutionConfig(10010,Path('/work/public/b.cert'),data['read_b'],data['pay_b'],
            18443,Path('/work/public/core.cookie'),'merchant')
        before=drained_channels()
        accounting=LndTreasuryObserver(host='127.0.0.1',port=10010,tls_certificate_path=config.lnd_tls_root_path,
            read_macaroon_path=config.lnd_read_macaroon_path,network=authority.network,
            expected_node_pubkey=authority.source_node).observe_accounting()
        assert before==drained_channels()
        assert (accounting.context.before_tip.height,accounting.context.before_tip.block_hash)==before[0]
        assert accounting.context.before_tip==accounting.context.after_tip
        assert accounting.coverage_complete and accounting.classified_local_commitment_floor_msat==200000000
        relay=FakeRelay()
        url=await relay.start()
        stop,mining_stop,pause,paused=asyncio.Event(),asyncio.Event(),asyncio.Event(),asyncio.Event()
        def mine():
            rpc('generatetoaddress',[1,mining_address],wallet='fund')
            synchronize()
        async def miner():
            for _ in range(240):
                await asyncio.sleep(0.5)
                if mining_stop.is_set(): return
                if pause.is_set():
                    paused.set()
                    continue
                await asyncio.to_thread(mine)
            raise AssertionError('owned SDK-death mining window exhausted')
        async def freeze():
            paused.clear()
            pause.set()
            await asyncio.wait_for(paused.wait(),5)
        manual_commands=[]
        async def operator(arguments):
            manual_commands.append(arguments[:2])
            completed=await asyncio.to_thread(subprocess.run,
                [sys.executable,'-c','import sys; from rill_cli.main import main; sys.exit(main(sys.argv[1:]))',
                    *arguments],capture_output=True,check=False,timeout=30)
            assert completed.returncode==0,'owned manual recovery command refused'
            assert completed.stderr==b'','owned manual recovery command emitted diagnostics'
            assert len(completed.stdout)<=4096
            return json.loads(completed.stdout)
        async def marker(expected,seconds):
            result=await asyncio.wait_for(child.stdout.readline(),seconds)
            if result!=expected:
                if child.returncode is None: child.kill()
                _output,diagnostic=await asyncio.wait_for(child.communicate(),5)
                for category in ('inputs','original_reservation','accounting','reservation_write','original_sdk'):
                    if ('PHASE: sdk_child_refused_'+category+'\n').encode() in diagnostic:
                        print('PHASE: sdk_child_'+category,file=sys.stderr)
                raise AssertionError('original SDK child marker refused')
        def financial_rows(journal,consumed,held):
            with sqlite3.connect((journal.directory/'inventory.sqlite').as_uri()+'?mode=ro',uri=True) as database:
                assert database.execute('SELECT payment_hash,consumed_msat FROM credits').fetchall()==[(credit.payment_hash,consumed)]
                assert database.execute('SELECT kind,owner,payment_hash,amount_msat FROM holds').fetchall()==(
                    [('conversion','owned_treasury_reverse_01',credit.payment_hash,105000000)] if held else [])
        child=None
        mining=None
        with LiveSessionStore.acquire(directory/'provider.sqlite',authority.network,data['identity'],
            data['policy'],crypto=crypto,custody_identity=str(data['custody']),public_keys=crypto) as store:
            chain=CoreTransactionReader(port=18443,cookie_path=config.core_cookie_path,network=authority.network,wallet='provider')
            held=LndHoldInvoices(host='127.0.0.1',port=10009,tls_certificate_path=data['cert_a'],macaroon_path=data['mac_a'],network=authority.network)
            decoder=LndInvoiceDecoder(host='127.0.0.1',port=10009,tls_certificate_path=data['cert_a'],macaroon_path=data['mac_a'],network=authority.network)
            lightning=LndPaymentSender(host='127.0.0.1',port=10009,tls_certificate_path=data['cert_a'],macaroon_path=data['mac_a'],network=authority.network)
            engine=SettlementEngine(store,chain,lightning,crypto,EngineSettings(allow_regtest_fixed_fee=True),hold_invoices=held)
            policy=ServicePolicy(network=authority.network,profiles=('ln-to-btc/v1',),profile='ln-to-btc/v1',
                amount_bands=((1000,1000000),),base_fee_sat=50,proportional_millionths=1000,slot='owned-treasury',
                relay_urls=(url,),provider_destination_script=data['provider_script'],
                quote=QuoteSchedule(max_funding_fee_sat=500,max_claim_fee_sat=400,max_refund_fee_sat=600,max_refund_delay_blocks=288))
            def claim_fee():  # the automatic reserve, sampled like rill_provider.cli
                fee=chain.next_block_fee()
                return ClaimFeeRate(rate_sat_kvb=fee.rate_sat_kvb,floor_sat_kvb=fee.floor_sat_kvb)
            service=HandshakeService(store,data['signer'],crypto,policy,chain_tip=chain.tip_height,invoice_decoder=decoder.decode,settlement=engine,hold_invoices=held,claim_fee=claim_fee)
            runner=asyncio.create_task(service.run(stop,tick_seconds=0.2))
            try:
                print('PHASE: original_sdk_child_start',file=sys.stderr)
                configuration={name:str(value) if isinstance(value,Path) else value for name,value in dataclasses.asdict(config).items()}
                envelope=dict(directory=str(directory),authority=authority.model_dump(mode='json'),credit=credit.model_dump(mode='json'),
                    config=configuration,credentials=dict(recipient=credentials.recipient,identity=credentials.identity),
                    relay_url=url,accounting_tip=[accounting.context.before_tip.height,accounting.context.before_tip.block_hash])
                payload=canonicalize(envelope)+b'\n'
                assert len(payload)<=65536
                child=await asyncio.create_subprocess_exec(sys.executable,'-c',SDK_DEATH_CHILD,
                    stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,limit=4096)
                child.stdin.write(payload)
                await child.stdin.drain()
                await marker(b'RESERVED\n',15)
                mining=asyncio.create_task(miner())
                await marker(b'CAPTURE_READY\n',60)
                await freeze()
                child.stdin.write(b'1')
                await child.stdin.drain()
                await marker(b'FUNDING_ACK\n',15)
                child.kill()
                assert await asyncio.wait_for(child.wait(),5)==-signal.SIGKILL
                output,errors=await asyncio.wait_for(child.communicate(),5)
                assert output==b'' and errors==b'','original SDK signer tripwire or diagnostics observed'
                print('PHASE: original_sdk_killed_before_claim_signer',file=sys.stderr)
                print('PHASE: sdk_death_journal_status',file=sys.stderr)
                journal=ConversionJournal.open(directory/'inventory',directory/'inventory-owner.json',authority)
                operation='owned_treasury_reverse_01'
                job=journal.status(operation)
                assert job.state=='dispatched' and job.receipt is None
                financial_rows(journal,0,True)
                print('PHASE: sdk_death_original_recovery',file=sys.stderr)
                initial=journal.directory/'recovery'/(operation+'.age')
                candidate=initial.with_suffix('.age.funded')
                hint_path=initial.with_suffix('.funding-inclusion.age')
                initial_cipher=_read_private(initial,262144)
                assert hashlib.sha256(initial_cipher).hexdigest()==job.recovery_sha256
                plaintext=decrypt_verified_plaintext(_read_private(candidate,262144),authority.network,credentials=credentials,crypto=crypto)
                original_plaintext=decrypt_verified_plaintext(initial_cipher,authority.network,credentials=credentials,crypto=crypto)
                inspect_recovery_successor(original_plaintext,plaintext,authority.network,crypto=crypto)
                print('PHASE: sdk_death_selected_binding',file=sys.stderr)
                recovery=json.loads(plaintext)
                original_recovery=json.loads(original_plaintext)
                assert recovery['user_secret']==original_recovery['user_secret']
                assert recovery['monotonic_knowledge']['preimage']==original_recovery['monotonic_knowledge']['preimage']
                assert recovery['monotonic_knowledge']['preimage_known'] is True
                assert recovery['monotonic_knowledge']['dangerous_signature_issued'] is False
                assert len(recovery['funding_history'])==1
                binding=FundingBinding.model_validate(recovery['funding_history'][0]['binding'])
                selected=inspect_recovery_selected_funding_context(plaintext,authority.network,
                    funding_attempt_id=binding.funding_attempt_id,binding_revision=binding.binding_revision,crypto=crypto)
                assert selected.binding==binding
                terms=selected.terms
                assert terms.network_identity==authority.network and terms.client_destination_script==authority.treasury_script
                assert terms.provider_identity_key==authority.provider_identity
                assert terms.invoice_binding.payment_hash==job.prepared.payment_hash
                assert terms.invoice_binding.bolt11_sha256==job.prepared.invoice_sha256
                assert int(terms.invoice_binding.amount_msat)==job.prepared.invoice_amount_msat
                print('PHASE: sdk_death_original_hint',file=sys.stderr)
                hint=read_funding_inclusion_hint(hint_path,credentials=credentials,operation_id=operation,
                    network=authority.network,original_recovery_sha256=job.recovery_sha256,binding=binding)
                assert hint.confirmations>=terms.funding_confirmations
                funding=await asyncio.to_thread(rpc,'gettransaction',[binding.funding_txid],wallet='provider')
                assert (hint.funding_block.height,hint.funding_block.block_hash)==(funding['blockheight'],funding['blockhash'])
                assert await asyncio.to_thread(rpc,'gettxout',[binding.funding_txid,binding.contract_vout,True]) is not None
                print('PHASE: sdk_death_original_source',file=sys.stderr)
                pending=call(b,b_secret,'ListPayments',ln.ListPaymentsRequest,ln.ListPaymentsResponse,ln.ListPaymentsRequest(include_incomplete=True))
                assert len(pending.payments)==1 and len(pending.payments[0].htlcs)==1
                assert pending.payments[0].status==ln.Payment.IN_FLIGHT
                assert pending.payments[0].htlcs[0].status==ln.HTLCAttempt.IN_FLIGHT
                assert pending.payments[0].payment_hash==job.prepared.payment_hash
                for _ in range(30):
                    if store._connection.execute('SELECT state FROM swaps').fetchall()==[('FUNDED',)]: break
                    await asyncio.sleep(0.2)
                assert store._connection.execute('SELECT state FROM swaps').fetchall()==[('FUNDED',)]
                print('PHASE: sdk_death_preserve_inputs',file=sys.stderr)
                generation=journal.begin_capacity_query()
                protected=immutable((initial,candidate,hint_path,data['read_b'],data['pay_b']))
                # Explicit test operator action, not a missing-marker retry.
                identity=directory/'manual-recovery.identity'
                network=directory/'manual-recovery-network.json'
                for path,document in ((identity,(credentials.identity+'\n').encode()),(network,canonicalize(authority.network.model_dump(mode='json')))):
                    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with os.fdopen(descriptor,'wb') as handle: handle.write(document)
                common=['--network',str(network),'--crypto-library','/work/provider/tmp/native/librill_crypto.so',
                    '--funding-attempt-id',binding.funding_attempt_id,'--binding-revision',str(binding.binding_revision),
                    '--rpc-cookie',str(config.core_cookie_path),'--rpc-port',str(config.core_port),'--identity',str(identity)]
                plan=directory/'manual-claim-plan.age'
                intent=directory/'manual-claim-intent.age'
                fee=int(terms.max_claim_fee_sat)
                assert fee>0
                print('PHASE: original_key_manual_claim_prepare',file=sys.stderr)
                prepared=await operator(['recover','prepare-claim',*common,'--fee-sat',str(fee),'--output',str(plan),str(candidate)])
                assert prepared['broadcast'] is False and prepared['preimage_external_disclosure'] is False
                assert prepared['fee_sat']==fee
                checked=verify_encrypted_claim_plan(_read_private(plan,262144),_read_private(candidate,262144),authority.network,
                    credentials=credentials,funding_attempt_id=binding.funding_attempt_id,binding_revision=binding.binding_revision,crypto=crypto)
                assert checked.claim_txid==prepared['claim_txid'] and checked.fee_sat==fee
                assert journal.status(operation)==job
                financial_rows(journal,0,True)
                print('PHASE: original_key_manual_claim_disclosure',file=sys.stderr)
                submitted=await operator(['recover','broadcast-claim',*common,'--plan',str(plan),'--intent',str(intent),
                    '--acknowledge-regtest-preimage-disclosure',str(candidate)])
                assert submitted['claim_txid']==checked.claim_txid
                assert submitted['submission']=='node_accepted' and submitted['disclosure']=='may_have_occurred'
                assert manual_commands==[['recover','prepare-claim'],['recover','broadcast-claim']]
                assert intent.is_file() and intent.stat().st_mode&0o777==0o600
                manual_protected=immutable((identity,network,plan,intent))
                assert journal.status(operation)==job
                financial_rows(journal,0,True)
                pause.clear()
                for _ in range(240):
                    await asyncio.sleep(0.25)
                    states=store._connection.execute('SELECT state FROM swaps').fetchall()
                    transaction=await asyncio.to_thread(rpc,'gettransaction',[checked.claim_txid],wallet='merchant')
                    if claim_receipt_ready(states,transaction,3): break
                else: raise AssertionError('original-key claim did not settle at approved depth')
                await freeze()
                mining_stop.set()
                await mining
                raw=bytes.fromhex(transaction['hex'])
                authorization=UnilateralAuthorization.from_terms(terms,FundingOutput(bytes.fromhex(binding.funding_txid),binding.contract_vout,
                    int(binding.contract_value_sat),bytes.fromhex(binding.contract_script_pubkey)),'claim',keys=crypto)
                actual=validate_unilateral_spend(raw,authorization,verifier=crypto)
                assert actual.txid==checked.claim_txid and actual.fee_sat==fee
                decoded=await asyncio.to_thread(rpc,'decoderawtransaction',[transaction['hex']])
                inputs=[item for item in decoded['vin'] if item.get('txid')==binding.funding_txid and item.get('vout')==binding.contract_vout]
                assert len(inputs)==1
                witness=inputs[0]['txinwitness']
                assert len(witness)==4 and witness[1]==recovery['monotonic_knowledge']['preimage']
                assert witness[2]==recovery['taproot_contract']['claim_script'] and witness[3]==recovery['taproot_contract']['claim_control_block']
                assert hashlib.sha256(bytes.fromhex(witness[1])).hexdigest()==job.prepared.payment_hash
                assert immutable((initial,candidate,hint_path,data['read_b'],data['pay_b']))==protected
                custody=DestinationCustody(network=authority.network,script=authority.treasury_script,core_wallet='merchant',destination_keys_controlled=True)
                before_receipt=inventory_snapshot(journal)
                print('PHASE: recovered_original_fresh_receipt',file=sys.stderr)
                receipt=await asyncio.to_thread(collect_conversion_receipt,journal,operation,config=config,credentials=credentials,crypto=crypto,
                    funding_recovery_path=candidate,funding_attempt_id=binding.funding_attempt_id,binding_revision=binding.binding_revision,
                    funding_block=None,funding_inclusion_hint_path=hint_path,claim_txid=checked.claim_txid,claim_path='unilateral',custody=custody)
                assert inventory_snapshot(journal)==before_receipt
                current=journal.begin_capacity_query()
                assert (current.journal_id,current.generation)==(generation.journal_id,generation.generation)
                assert receipt.payment_hash==job.prepared.payment_hash and receipt.destination_script==authority.treasury_script
                assert receipt.destination_txid==checked.claim_txid and receipt.destination_value_sat>=job.prepared.minimum_net_output_sat
                assert receipt.confirmation_blocks>=3
                financial_rows(journal,0,True)
                invoices=call(b,b_secret,'ListInvoices',ln.ListInvoiceRequest,ln.ListInvoiceResponse,ln.ListInvoiceRequest())
                assert len(invoices.invoices)==1 and invoices.invoices[0].settled and invoices.invoices[0].amt_paid_msat==credit.amount_msat
                payments=call(b,b_secret,'ListPayments',ln.ListPaymentsRequest,ln.ListPaymentsResponse,ln.ListPaymentsRequest(include_incomplete=True))
                assert len(payments.payments)==1
                payment=payments.payments[0]
                assert payment.status==ln.Payment.SUCCEEDED and payment.payment_hash==receipt.payment_hash
                assert len(payment.htlcs)==1 and payment.htlcs[0].status==ln.HTLCAttempt.SUCCEEDED
                assert payment.value_msat==receipt.amount_msat and payment.fee_msat==receipt.routing_fee_msat
                assert payment.htlcs[0].route.first_hop_amount_msat==receipt.amount_msat+receipt.routing_fee_msat
                print('PHASE: recovered_original_saved_cli_completion',file=sys.stderr)
                completed=await cli_completion(journal,authority,config,credentials,candidate,binding.model_dump(mode='json'),
                    dict(blockheight=hint.funding_block.height,blockhash=hint.funding_block.block_hash),checked.claim_txid,custody,
                    saved_hint_path=hint_path,claim_path='unilateral')
                assert completed.state=='complete' and completed.receipt is not None
                assert completed.receipt==receipt
                current=journal.begin_capacity_query()
                assert (current.journal_id,current.generation)==(generation.journal_id,generation.generation+1)
                financial_rows(journal,receipt.amount_msat+receipt.routing_fee_msat,False)
                assert immutable((initial,candidate,data['read_b'],data['pay_b']))==protected[:2]+protected[3:]
                assert immutable((identity,network,plan,intent))==manual_protected
                final=call(b,b_secret,'ListPayments',ln.ListPaymentsRequest,ln.ListPaymentsResponse,ln.ListPaymentsRequest(include_incomplete=True))
                assert final.SerializeToString(deterministic=True)==payments.SerializeToString(deterministic=True)
                assert store._connection.execute('SELECT state FROM swaps').fetchall()==[('SETTLED',)]
                return dict(original_reverse_receipt=True,source_debit_msat=receipt.amount_msat+receipt.routing_fee_msat,
                    destination_value_sat=receipt.destination_value_sat,claim_depth=receipt.confirmation_blocks,original_source_attempts=1,
                    inventory_hold_retained=False,verified_completion=True,accounting_admission=True,operator_cli_completion=True,
                    original_funding_hint_retained=True,saved_operator_cli_completion=True,original_claim_path='unilateral',
                    original_sdk_sigkilled=True,original_key_manual_recovery=True,original_sdk_claim_signer_acquired=False)
            finally:
                if child is not None and child.returncode is None:
                    child.kill()
                    await asyncio.wait_for(child.communicate(),5)
                mining_stop.set()
                try:
                    if mining is not None: await mining
                finally:
                    stop.set()
                    try: await runner
                    finally: await relay.stop()
"""


def _program() -> str:
    fixture = import_module("test_merchant_conversion_pinned")
    original = fixture._program(  # noqa: SLF001 - unchanged owned fixture template
        completion=True,
        cli_completion=True,
        retain_funding_inclusion=True,
        saved_cli_completion=True,
    )
    tree = ast.parse(original)
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "funded_reverse"
    ]
    assert len(functions) == 1
    target = functions[0]
    assert target.end_lineno is not None
    lines = original.splitlines(keepends=True)
    return (
        "".join(lines[: target.lineno - 1])
        + f"    SDK_DEATH_CHILD = {SDK_CHILD!r}\n"
        + SDK_DEATH_RECOVERY
        + "".join(lines[target.end_lineno :])
    )


def test_original_sdk_death_program_compiles_at_separate_original_owner_boundary() -> None:
    compile(SDK_CHILD, "<original-sdk-child>", "exec")
    program = _program()
    tree = ast.parse(program)
    assert (
        len(
            [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.AsyncFunctionDef) and node.name == "funded_reverse"
            ]
        )
        == 1
    )
    assert "SIGNER_TRIPWIRE" in SDK_CHILD
    assert "print('FUNDING_ACK',flush=True)" in SDK_CHILD
    assert "-signal.SIGKILL" in program
    assert "--acknowledge-regtest-preimage-disclosure" in program
    assert "fee=int(terms.max_claim_fee_sat)" in program
    assert "confirmation_blocks=3" in SDK_CHILD
    compile(program, "<original-sdk-death-recovery>", "exec")


def test_original_child_uses_the_unchanged_fixture_offer_and_payment_limits() -> None:
    fixture = import_module("test_merchant_conversion_pinned")
    original = fixture._program(completion=True)  # noqa: SLF001 - protect the pre-existing approved ceilings

    def limits(program: str) -> dict[str, object]:
        calls = [
            node
            for node in ast.walk(ast.parse(program))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ReverseSwapLimits"
        ]
        assert len(calls) == 1
        return {
            argument.arg: ast.literal_eval(argument.value)
            for argument in calls[0].keywords
            if argument.arg is not None
        }

    assert limits(SDK_CHILD) == limits(original)


@pytest.mark.parametrize(
    "document",
    [b"PRIVATE_CANARY\n", b'{"authority":"PRIVATE_CANARY"}\n', b"PRIVATE_CANARY" * 6000 + b"\n"],
    ids=["malformed", "wrong-shape", "oversized"],
)
def test_original_child_refuses_unknown_or_oversized_envelopes_without_diagnostics(
    document: bytes,
) -> None:
    result = subprocess.run(  # noqa: S603 - current interpreter and fixed test program, bounded malformed stdin only
        [sys.executable, "-c", SDK_CHILD],
        input=document,
        capture_output=True,
        check=False,
        timeout=5,
        env={
            **os.environ,
            "PYTHONPATH": os.pathsep.join(
                [str(Path(__file__).resolve().parents[2] / "rill-cli/src"), *sys.path]
            ),
        },
    )
    assert result.returncode == 2
    assert result.stdout == b""
    assert result.stderr == b"PHASE: sdk_child_refused_inputs\n"


@pytest.mark.lnd
@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1" or os.environ.get("RILLSWAP_RUN_BUN_MERCHANT") != "1",
    reason="explicit original SDK death and manual same-key recovery opt-ins",
)
def test_pinned_original_sdk_death_before_claim_recovers_with_original_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = import_module("test_merchant_conversion_pinned")
    program = _program()

    def selected(**controls: Any) -> str:  # noqa: ANN401 - reuse the existing controlled sidecar launcher, not its runtime scenario
        assert controls == {
            "completion": True,
            "crash_boundary": None,
            "restart": False,
            "cli_completion": True,
            "retain_funding_inclusion": True,
            "saved_cli_completion": True,
        }
        return program

    monkeypatch.setattr(fixture, "_program", selected)
    evidence = fixture._funded_evidence(  # noqa: SLF001 - existing owned daemon/merchant/native setup and outer financial assertions
        tmp_path,
        completion=True,
        cli_completion=True,
        retain_funding_inclusion=True,
        saved_cli_completion=True,
    )
    assert evidence["original_sdk_sigkilled"] is True
    assert evidence["original_key_manual_recovery"] is True
    assert evidence["original_sdk_claim_signer_acquired"] is False
    assert evidence["saved_operator_cli_completion"] is True
    assert evidence["original_claim_path"] == "unilateral"
