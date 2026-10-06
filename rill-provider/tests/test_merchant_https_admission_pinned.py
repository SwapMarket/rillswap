"""Owned native LND payment proves bound HTTPS admission and durable acceptance."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from pathlib import Path

import pytest
from test_bun_merchant_pinned import BUN_REVISION, BUN_SHA256
from test_lnd_payment_pinned import CHANNEL_SETUP, ROOT, _run_two_node_sidecar
from test_lnd_payment_tls import _certificate

ADMISSION_PROGRAM = (
    CHANNEL_SETUP  # noqa: S608 - static fixture program; its SQL has no interpolated input
    + """
    import selectors, socket, sqlite3, ssl, subprocess, tempfile
    from pathlib import Path
    from Cryptodome.Signature import eddsa
    def private_file(directory, name, content):
        path = directory / name
        with path.open('xb') as output:
            os.chmod(path, 0o600)
            output.write(content)
        return path
    with tempfile.TemporaryDirectory(prefix='merchant-admission-', dir='/tmp') as root:
        directory = Path(root)
        os.chmod(directory, 0o700)
        cert = private_file(directory, 'merchant.cert',
            Path('/work/proof-tls/merchant.cert').read_bytes())
        key = private_file(directory, 'merchant.key',
            Path('/work/proof-tls/merchant.key').read_bytes())
        lnd_cert = private_file(directory, 'lnd.cert', Path('/work/public/b.cert').read_bytes())
        issuance = bytes.fromhex(call(b, b_secret, 'BakeMacaroon',
            ln.BakeMacaroonRequest, ln.BakeMacaroonResponse,
            ln.BakeMacaroonRequest(permissions=[ln.MacaroonPermission(entity=entity, action=action)
                for entity, action in (('info', 'read'), ('invoices', 'read'),
                    ('invoices', 'write'))],
                root_key_id=0, allow_external_permissions=False)).macaroon)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        origin = 'https://127.0.0.1:' + str(port)
        admin = secrets.token_urlsafe(32)
        config = {'origin': origin, 'receiver': b_key, 'endpoint': 'https://127.0.0.1:8081',
            'ledgerPath': str(directory / 'merchant.sqlite'),
            'consumerPath': str(directory / 'consumer.sqlite'), 'certificatePath': str(lnd_cert),
            'listenerCertificatePath': str(cert), 'listenerKeyPath': str(key),
            'listenerPort': str(port)}
        for name, content in (('issuanceKeyPath', secrets.token_bytes(32)),
            ('statusKeyPath', secrets.token_bytes(32)), ('eventKeyPath', secrets.token_bytes(32)),
            ('adminTokenPath', admin.encode()), ('macaroonPath', issuance)):
            config[name] = str(private_file(directory, name, content))
        config_path = private_file(directory, 'config.json', json.dumps(config).encode())
        signing_key = eddsa.import_private_key(Path(config['eventKeyPath']).read_bytes())
        expected_public_key = signing_key.public_key().export_key(format='raw').hex()
        child = subprocess.Popen(['/work/bun', '/work/merchant.js', str(config_path)],
            env=dict(os.environ, RILLSWAP_MERCHANT_ADMISSION='1'),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pending = bytearray()
        def line(seconds):
            deadline = time.monotonic() + seconds
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while b'\\n' not in pending:
                    remaining = deadline - time.monotonic()
                    assert remaining > 0 and len(pending) <= 8192, 'admission pipe refused'
                    assert selector.select(timeout=remaining), 'admission pipe expired'
                    chunk = os.read(child.stdout.fileno(), 8193 - len(pending))
                    assert chunk, 'admission pipe closed'
                    pending.extend(chunk)
            end = pending.index(b'\\n')
            assert end <= 8192, 'admission message too large'
            result = json.loads(bytes(pending[:end]))
            del pending[:end + 1]
            assert isinstance(result, dict), 'admission message invalid'
            return result
        def reply(value):
            child.stdin.write(json.dumps(value).encode() + b'\\n')
            child.stdin.flush()
        consumed = False
        try:
            ready = line(10)
            assert set(ready) == {'kind', 'port', 'publicKey'}
            assert ready['kind'] == 'server-ready' and ready['port'] == port
            assert ready['publicKey'] == expected_public_key
            tls = ssl.create_default_context(cafile=str(cert))
            with httpx.Client(base_url=origin, verify=tls, timeout=5,
                follow_redirects=False, trust_env=False) as merchant:
                headers = {'Authorization': 'Bearer ' + admin, 'Origin': origin}
                created = merchant.post('/v1/intents', headers=dict(headers,
                    **{'Idempotency-Key': 'merchant_admission_intent_01'}), json={
                    'orderRef': 'owned-admission-order', 'amountMsat': '1000000',
                    'expiresAt': int(time.time()) + 600})
                assert created.status_code == 201
                intent = created.json()
                intent_path = '/v1/intents/' + intent['id']
                issued = merchant.post(intent_path + '/attempts', headers=dict(headers,
                    **{'Idempotency-Key': 'merchant_admission_attempt_01'}), json={})
                assert issued.status_code == 201 and issued.json()['attempt'] is None
                reply({'kind': 'exercise-withheld', 'intentId': intent['id'],
                    'statusToken': intent['statusToken']})
                assert line(10) == {'kind': 'withheld', 'walletCalls': 0, 'checkpointCount': 0}
                registered = merchant.put(intent_path + '/order-binding', headers=headers,
                    json={'orderRef': 'owned-admission-order', 'amountMsat': '1000000'})
                assert registered.status_code == 200
                pinned = merchant.get(intent_path, headers=headers)
                assert pinned.status_code == 200 and pinned.json()['status'] == 'waiting'
                attempt = pinned.json()['attempt']
                terms, bolt11 = attempt['terms'], attempt['invoice']
                assert terms['intentId'] == intent['id'] and terms['merchantOrigin'] == origin
                assert terms['receiver'] == b_key and terms['network'] == 'regtest'
                assert terms['amountMsat'] == '1000000' and int(time.time()) < terms['expiresAt']
                decoded = call(a, a_secret, 'DecodePayReq', ln.PayReqString, ln.PayReq,
                    ln.PayReqString(pay_req=bolt11))
                assert decoded.num_msat == 1000000 and decoded.destination == b_key
                assert decoded.payment_hash == terms['paymentHash']
                owned = call(b, b_secret, 'LookupInvoice', ln.PaymentHash, ln.Invoice,
                    ln.PaymentHash(r_hash=bytes.fromhex(decoded.payment_hash)))
                assert owned.payment_request == bolt11
                assert owned.r_hash.hex() == decoded.payment_hash
                assert owned.value_msat == 1000000 and owned.amt_paid_msat == 0
                assert owned.state == ln.Invoice.OPEN
                assert int(time.time()) < owned.creation_date + owned.expiry
                channel_id = views[0][0].chan_id
                route_deadline = time.monotonic() + 30
                while time.monotonic() < route_deadline:
                    try:
                        routes = call(a, a_secret, 'QueryRoutes', ln.QueryRoutesRequest,
                            ln.QueryRoutesResponse, ln.QueryRoutesRequest(pub_key=b_key,
                                amt_msat=1000000, final_cltv_delta=decoded.cltv_expiry,
                                outgoing_chan_ids=[channel_id], fee_limit=ln.FeeLimit(fixed_msat=0),
                                use_mission_control=False),
                            timeout=min(2, route_deadline - time.monotonic()))
                        if (routes.routes and len(routes.routes[0].hops) == 1
                            and routes.routes[0].hops[0].chan_id == channel_id
                            and routes.routes[0].total_amt_msat == 1000000): break
                    except grpc.RpcError:
                        pass
                    time.sleep(0.1)
                else: raise AssertionError('exact native admission route unavailable')
                reply({'kind': 'authorized'})
                message = line(10)
                assert set(message) == {'kind', 'invoice', 'feeMsat'}
                assert message['kind'] == 'pay' and message['invoice'] == bolt11
                assert message['feeMsat'] == '0'
                assert not consumed
                consumed = True
                router_channel = dial(Path('/work/public/a.cert').read_bytes(), 10009)
                try:
                    send = router_channel.unary_stream('/routerrpc.Router/SendPaymentV2',
                        request_serializer=router.SendPaymentRequest.SerializeToString,
                        response_deserializer=ln.Payment.FromString)
                    stream = send(router.SendPaymentRequest(payment_request=bolt11, max_parts=1,
                        outgoing_chan_ids=[channel_id], fee_limit_msat=0, timeout_seconds=30,
                        no_inflight_updates=False), metadata=metadata(a_secret), timeout=90)
                    try:
                        completed = None
                        for payment in stream:
                            assert payment.payment_hash == decoded.payment_hash
                            if payment.status == ln.Payment.SUCCEEDED:
                                completed = payment; break
                            if payment.status == ln.Payment.FAILED:
                                raise AssertionError('native admission payment failed')
                        assert completed is not None
                    finally: stream.cancel()
                finally: router_channel.close()
                assert completed.value_msat == 1000000 and completed.fee_msat == 0
                successful = [part for part in completed.htlcs
                    if part.status == ln.HTLCAttempt.SUCCEEDED]
                assert len(successful) == 1 and len(completed.htlcs) == 1
                assert successful[0].route.hops[0].chan_id == channel_id
                assert successful[0].route.first_hop_amount_msat == 1000000
                reply({'paid': True})
                assert line(20) == {'kind': 'complete', 'invoiceWithheld': True,
                    'singleDispatch': True, 'receiverAccepted': True, 'durableAcceptance': True,
                    'replayDeduplicated': True, 'noExternalFulfillment': True}
                child.stdin.close()
                assert child.wait(timeout=5) == 0, 'admission runner failed'
                assert not pending and child.stdout.read(8193) == b'', 'unexpected admission output'
                assert child.stderr.read(8193) == b'', 'admission diagnostics refused'
                invoices = call(b, b_secret, 'ListInvoices', ln.ListInvoiceRequest,
                    ln.ListInvoiceResponse, ln.ListInvoiceRequest(num_max_invoices=10))
                assert len(invoices.invoices) == 1
                assert invoices.invoices[0].state == ln.Invoice.SETTLED
                assert invoices.invoices[0].r_hash.hex() == decoded.payment_hash
                with sqlite3.connect('file:' + config['consumerPath'] + '?mode=ro',
                    uri=True) as stored:
                    bindings = stored.execute('SELECT order_ref,amount_msat,payment_hash '
                        'FROM orders').fetchall()
                    acceptances = stored.execute('SELECT event_id,order_ref,envelope '
                        'FROM acceptances').fetchall()
                assert bindings == [('owned-admission-order', '1000000', decoded.payment_hash)]
                assert len(acceptances) == 1 and acceptances[0][1] == 'owned-admission-order'
                envelope = json.loads(acceptances[0][2])
                event = envelope['event']
                assert envelope['publicKey'] == expected_public_key
                assert event['id'] == acceptances[0][0] and event['intentId'] == intent['id']
                assert event['paymentHash'] == decoded.payment_hash
                assert event['amountMsat'] == '1000000' and event['merchantOrigin'] == origin
                signed = json.dumps(['rillswap-payment-event/1', event['version'], event['id'],
                    event['merchantOrigin'], event['type'], event['intentId'], event['attemptId'],
                    event['paymentHash'], event['amountMsat'], event['acceptedAt']],
                    separators=(',', ':')).encode()
                eddsa.new(signing_key.public_key(), 'rfc8032').verify(signed,
                    bytes.fromhex(envelope['signature']))
                print(json.dumps({'funding_txid': txid, 'vout': point.output_index,
                    'capacity_sat': views[0][0].capacity, 'confirmations': output['confirmations'],
                    'invoice_withheld': True, 'single_native_dispatch': True,
                    'receiver_accepted': True, 'durable_acceptance': True,
                    'replay_deduplicated': True, 'no_external_fulfillment': True}))
        except Exception:
            raise AssertionError('owned admission conformance unresolved') from None
        finally:
            try:
                if child.poll() is None: child.terminate()
                try: child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait(timeout=5)
            finally:
                if not child.stdin.closed: child.stdin.close()
                child.stdout.close(); child.stderr.close()
"""
)


def test_admission_program_compiles_without_running() -> None:
    assert "\x00" not in ADMISSION_PROGRAM
    compile(ADMISSION_PROGRAM, "<owned-merchant-admission>", "exec")


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1" or os.environ.get("RILLSWAP_RUN_BUN_MERCHANT") != "1",
    reason="set both opt-in flags for native funded merchant admission conformance",
)
def test_pinned_https_native_admission_and_bound_acceptance(tmp_path: Path) -> None:
    bun = ROOT.parent / "tmp/toolchains/bun-v1.3.11/bun"
    assert hashlib.sha256(bun.read_bytes()).hexdigest() == BUN_SHA256
    revision = subprocess.run(  # noqa: S603 - checksum-verified test executable
        [str(bun), "--revision"], capture_output=True, text=True, check=True, timeout=5
    )
    assert revision.stdout.strip() == BUN_REVISION
    with tempfile.TemporaryDirectory(prefix="merchant-admission-", dir=ROOT.parent / "tmp") as root:
        staging = Path(root)
        staging.chmod(0o700)
        tls = staging / "tls"
        tls.mkdir(mode=0o700)
        certificate, _private_key = _certificate(tls)
        certificate.rename(tls / "merchant.cert")
        (tls / "local.key").rename(tls / "merchant.key")
        for path in tls.iterdir():
            path.chmod(0o600)
        bundle = staging / "merchant.js"
        built = subprocess.run(  # noqa: S603 - checksum-verified compiler, owned runner
            [
                str(bun),
                "build",
                "tests/regtestMerchantHttpsAdmission.ts",
                "--target",
                "bun",
                "--outfile",
                str(bundle),
            ],
            cwd=ROOT.parent / "rill-payments",
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert built.returncode == 0, "merchant admission bundle refused"
        evidence = _run_two_node_sidecar(
            tmp_path,
            ADMISSION_PROGRAM,
            prefix="merchant-admission",
            deadline=300,
            profile="merchant_proof",
            merchant_bun_bundle=bundle,
            merchant_proof_tls_directory=tls,
        )
    for field in (
        "invoice_withheld",
        "single_native_dispatch",
        "receiver_accepted",
        "durable_acceptance",
        "replay_deduplicated",
        "no_external_fulfillment",
    ):
        assert evidence[field] is True
