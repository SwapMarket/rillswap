"""Explicit funded HTTPS/LND/Core provenance, not inventory or conversion authority."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from pathlib import Path

import pytest
from test_bun_merchant_pinned import BUN_REVISION, BUN_SHA256
from test_lnd_payment_pinned import (
    CHANNEL_SETUP,
    ROOT,
    _merchant_proof_mounts,
    _run_two_node_sidecar,
)
from test_lnd_payment_tls import _certificate

FUNDED_MERCHANT_PROOF = (
    CHANNEL_SETUP
    + """
    import hashlib, selectors, socket, sqlite3, ssl, subprocess, tempfile
    from pathlib import Path
    from Cryptodome.Signature import eddsa
    from rill_core.networks import REGTEST_CONSENSUS_PROFILE
    from rill_core.wire.types import NetworkIdentity
    from rill_cli.conversion_journal import SourceAuthority
    from rill_cli.merchant_credit import MerchantSourcePin
    from rill_cli.merchant_source import (
        MerchantCreditCollector, MerchantSourceConfig, MerchantSourceError)
    print('PHASE: merchant_proof_inputs', file=sys.stderr)
    network = NetworkIdentity(family='bitcoin', name='regtest',
        genesis_hash='0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
        signet_challenge=None, consensus_profile=REGTEST_CONSENSUS_PROFILE,
        deployment_namespace='merchant-source-proof/1')
    def private_file(directory, name, contents):
        path = directory / name
        with path.open('xb') as stream:
            os.chmod(path, 0o600)
            stream.write(contents)
        return path
    def bake(permissions):
        return bytes.fromhex(call(b, b_secret, 'BakeMacaroon',
            ln.BakeMacaroonRequest, ln.BakeMacaroonResponse,
            ln.BakeMacaroonRequest(permissions=permissions, root_key_id=0,
                allow_external_permissions=False)).macaroon)
    def immutable(paths):
        result = []
        for path in paths:
            info = path.lstat()
            assert path.is_file() and not path.is_symlink() and info.st_nlink == 1
            assert info.st_mode & 0o077 == 0
            result.append((info.st_dev, info.st_ino, info.st_mode,
                hashlib.sha256(path.read_bytes()).hexdigest()))
        return result
    def logical(path):
        with sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True) as connection:
            return tuple(connection.iterdump())
    with tempfile.TemporaryDirectory(prefix='merchant-proof-', dir='/tmp') as root:
        directory = Path(root)
        os.chmod(directory, 0o700)
        cert = private_file(directory, 'merchant.cert',
            Path('/work/proof-tls/merchant.cert').read_bytes())
        key = private_file(directory, 'merchant.key',
            Path('/work/proof-tls/merchant.key').read_bytes())
        lnd_cert = private_file(directory, 'lnd.cert', Path('/work/public/b.cert').read_bytes())
        issuance = bake([ln.MacaroonPermission(entity=entity, action=action)
            for entity, action in (('info', 'read'), ('invoices', 'read'), ('invoices', 'write'))])
        collector_mac = bake([ln.MacaroonPermission(entity='uri', action=method) for method in (
            '/lnrpc.Lightning/GetInfo', '/invoicesrpc.Invoices/LookupInvoiceV2',
            '/lnrpc.Lightning/DecodePayReq')])
        admin = secrets.token_urlsafe(32)
        signing_key = secrets.token_bytes(32)
        signing_private = eddsa.import_private_key(signing_key)
        public_key = signing_private.public_key().export_key(format='raw').hex()
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            merchant_port = reservation.getsockname()[1]
        origin = 'https://127.0.0.1:' + str(merchant_port)
        config = {'profile': 'regtest-merchant-https/1', 'origin': origin,
            'receiver': b_key, 'endpoint': 'https://127.0.0.1:8081',
            'ledgerPath': str(directory / 'merchant.sqlite'), 'certificatePath': str(lnd_cert),
            'listenerCertificatePath': str(cert), 'listenerKeyPath': str(key),
            'listenerPort': str(merchant_port)}
        for field, content in (('issuanceKeyPath', secrets.token_bytes(32)),
            ('statusKeyPath', secrets.token_bytes(32)), ('eventKeyPath', signing_key),
            ('adminTokenPath', admin.encode()), ('macaroonPath', issuance)):
            config[field] = str(private_file(directory, field, content))
        mac_path = private_file(directory, 'collector.macaroon', collector_mac)
        config_path = private_file(directory, 'config.json', json.dumps(config).encode())
        inputs = [config_path, cert, key, lnd_cert, mac_path] + [Path(config[field]) for field in (
            'issuanceKeyPath', 'statusKeyPath', 'eventKeyPath', 'adminTokenPath', 'macaroonPath')]
        before_inputs = immutable(inputs)
        environment = dict(os.environ, RILLSWAP_REGTEST_MERCHANT='1')
        provision = subprocess.run(
            ['/work/bun', '/work/merchant.js', 'provision-https', str(config_path)],
            env=environment, capture_output=True, timeout=15)
        assert provision.returncode == 0 and provision.stdout == b'{"provisioned":true}\\n'
        assert provision.stderr == b''
        child = subprocess.Popen(
            ['/work/bun', '/work/merchant.js', 'serve-https', str(config_path)],
            env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as ready_selector:
                ready_selector.register(child.stdout, selectors.EVENT_READ)
                assert ready_selector.select(timeout=10), 'owned merchant did not become ready'
                readiness = json.loads(os.read(child.stdout.fileno(), 4096))
            assert readiness == {'ready': True, 'port': merchant_port, 'publicKey': public_key}
            print('PHASE: merchant_proof_issuance', file=sys.stderr)
            tls = ssl.create_default_context(cafile=str(cert))
            with httpx.Client(base_url=origin, verify=tls, timeout=5,
                follow_redirects=False, trust_env=False) as merchant:
                created = merchant.post('/v1/intents', headers={
                    'Authorization': 'Bearer ' + admin, 'Origin': origin,
                    'Idempotency-Key': 'merchant_proof_intent_01'}, json={
                    'orderRef': 'owned-funded-proof', 'amountMsat': '1000000',
                    'expiresAt': int(time.time()) + 600})
                assert created.status_code == 201
                intent = created.json()
                intent_path = '/v1/intents/' + intent['id']
                issued = merchant.post(intent_path + '/attempts', headers={
                    'Authorization': 'Bearer ' + admin, 'Origin': origin,
                    'Idempotency-Key': 'merchant_proof_attempt_01'}, json={})
                assert issued.status_code == 201
                headers = {'Authorization': 'Bearer ' + intent['statusToken'], 'Origin': origin}
                for _ in range(100):
                    observed = merchant.get(intent_path, headers=headers)
                    assert observed.status_code == 200
                    current = observed.json()
                    if current['attempt'] is not None: break
                    time.sleep(0.1)
                else: raise AssertionError('ordinary merchant invoice was not issued')
                attempt = current['attempt']
                bolt11 = attempt['invoice']
                terms = attempt['terms']
                assert terms['merchantOrigin'] == origin and terms['receiver'] == b_key
                assert terms['amountMsat'] == '1000000' and terms['network'] == 'regtest'
                print('PHASE: merchant_proof_payer_decode', file=sys.stderr)
                decoded = call(a, a_secret, 'DecodePayReq', ln.PayReqString, ln.PayReq,
                    ln.PayReqString(pay_req=bolt11))
                assert decoded.num_msat == 1000000 and decoded.destination == b_key
                channel_id = views[0][0].chan_id
                print('PHASE: merchant_proof_route_readiness', file=sys.stderr)
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
                else: raise AssertionError('exact direct route unavailable')
                print('PHASE: merchant_proof_payment', file=sys.stderr)
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
                                raise AssertionError('owned ordinary invoice payment failed')
                        assert completed is not None
                    finally: stream.cancel()
                finally: router_channel.close()
                assert completed.value_msat == 1000000 and completed.fee_msat == 0
                successful = [part for part in completed.htlcs
                    if part.status == ln.HTLCAttempt.SUCCEEDED]
                assert len(successful) == 1 and len(completed.htlcs) == 1
                assert successful[0].route.hops[0].chan_id == channel_id
                assert successful[0].route.first_hop_amount_msat == 1000000
                print('PHASE: merchant_proof_acceptance', file=sys.stderr)
                for _ in range(100):
                    paid = merchant.get(intent_path, headers=headers).json()
                    if paid['status'] == 'paid': break
                    time.sleep(0.1)
                else: raise AssertionError('merchant did not accept original ordinary invoice')
                assert paid['attempt'] == attempt
                events = merchant.get(intent_path + '/events', headers=headers)
                assert events.status_code == 200 and len(events.json()) == 1
                address = rpc('getnewaddress', ['', 'bech32m'], wallet='fund')
                owned = rpc('getaddressinfo', [address], wallet='fund')
                assert owned['ismine'] and owned['scriptPubKey'].startswith('5120')
                authority = SourceAuthority(source_node=b_key, network=network,
                    source_epoch=hashlib.sha256(b'merchant-proof-owned-epoch').hexdigest(),
                    exclusive_wallet=True, commitments_known=True, fixed_reserve_msat=1000,
                    treasury_script=owned['scriptPubKey'], provider_identity=a_key[2:])
                pin = MerchantSourcePin(merchant_origin=origin, event_public_key=public_key,
                    source_node=b_key, network=network)
                leaf = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
                source_config = MerchantSourceConfig(leaf, cert, 10010, lnd_cert, mac_path,
                    18443, Path('/work/public/core.cookie'))
                before_history = logical(Path(config['ledgerPath']))
                print('PHASE: merchant_proof_collection', file=sys.stderr)
                collector = MerchantCreditCollector(authority, pin, source_config)
                credit = collector.acquire(intent['id'], intent['statusToken'])
                assert credit.payment_hash == decoded.payment_hash
                assert credit.invoice_sha256 == hashlib.sha256(bolt11.encode('ascii')).hexdigest()
                assert credit.amount_msat == 1000000
                assert logical(Path(config['ledgerPath'])) == before_history
                assert immutable(inputs) == before_inputs
                all_invoices = call(b, b_secret, 'ListInvoices', ln.ListInvoiceRequest,
                    ln.ListInvoiceResponse, ln.ListInvoiceRequest(num_max_invoices=10))
                assert len(all_invoices.invoices) == 1
                assert all_invoices.invoices[0].state == ln.Invoice.SETTLED
                assert all_invoices.invoices[0].r_hash.hex() == credit.payment_hash
                print(json.dumps({'funding_txid': txid, 'vout': point.output_index,
                    'capacity_sat': views[0][0].capacity, 'confirmations': output['confirmations'],
                    'merchant_source_provenance': True, 'agreed_amount_msat': credit.amount_msat,
                    'single_ordinary_invoice': True, 'single_payer_attempt': True,
                    'merchant_history_unchanged': True, 'private_inputs_unchanged': True}))
        finally:
            try:
                if child.poll() is None:
                    child.terminate()
                try: child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait(timeout=5)
                assert child.returncode == 0, 'owned merchant shutdown failed'
                assert child.stderr.read(8193) == b'', 'owned merchant emitted diagnostics'
            finally: child.stdout.close(); child.stderr.close()
"""
)


def test_funded_proof_program_compiles_without_running() -> None:
    assert "\x00" not in FUNDED_MERCHANT_PROOF
    compile(FUNDED_MERCHANT_PROOF, "<owned-merchant-source-proof>", "exec")


def test_proof_inputs_are_refused_before_resources_for_legacy_profiles(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="isolated proof profile"):
        _merchant_proof_mounts("baseline", None, tmp_path)
    with pytest.raises(ValueError, match="explicit bundle and TLS"):
        _merchant_proof_mounts("merchant_proof", None, None)


@pytest.mark.parametrize(
    "fault", ["outside", "public_directory", "public_key", "missing_key", "linked_key"]
)
def test_proof_tls_mount_requires_private_owned_local_inputs(tmp_path: Path, fault: str) -> None:
    with tempfile.TemporaryDirectory(prefix="proof-inputs-", dir=ROOT.parent / "tmp") as root:
        directory = Path(root)
        directory.chmod(0o700)
        for name in ("merchant.cert", "merchant.key"):
            path = directory / name
            path.write_bytes(b"test-only-invalid-pem")
            path.chmod(0o600)
        if fault == "outside":
            directory = tmp_path
        elif fault == "public_directory":
            directory.chmod(0o755)
        elif fault == "public_key":
            (directory / "merchant.key").chmod(0o644)
        elif fault == "missing_key":
            (directory / "merchant.key").unlink()
        else:
            (directory / "merchant.key").unlink()
            (directory / "merchant.key").symlink_to(directory / "merchant.cert")
        with pytest.raises(ValueError, match="proof TLS input"):
            _merchant_proof_mounts("merchant_proof", Path(root) / "merchant.js", directory)


def test_proof_mount_exposes_only_cli_source_not_private_cli_working_state() -> None:
    with tempfile.TemporaryDirectory(prefix="proof-inputs-", dir=ROOT.parent / "tmp") as root:
        directory = Path(root)
        directory.chmod(0o700)
        for name in ("merchant.cert", "merchant.key"):
            path = directory / name
            path.write_bytes(b"test-only-invalid-pem")
            path.chmod(0o600)
        mounts = _merchant_proof_mounts("merchant_proof", directory / "merchant.js", directory)
        assert f"type=bind,src={ROOT.parent / 'rill-cli/src'},dst=/work/cli/src,readonly" in mounts
        assert f"type=bind,src={ROOT.parent / 'rill-cli'},dst=/work/cli,readonly" not in mounts


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1" or os.environ.get("RILLSWAP_RUN_BUN_MERCHANT") != "1",
    reason="set both opt-in flags for funded merchant/source provenance",
)
def test_pinned_https_merchant_source_credit_provenance(tmp_path: Path) -> None:
    """One owned payment, actual HTTPS/ordinary LND/Core, no journal or swap."""
    bun = ROOT.parent / "tmp/toolchains/bun-v1.3.11/bun"
    assert hashlib.sha256(bun.read_bytes()).hexdigest() == BUN_SHA256
    revision = subprocess.run(  # noqa: S603 - checksum-verified test executable
        [str(bun), "--revision"], capture_output=True, text=True, check=True, timeout=5
    )
    assert revision.stdout.strip() == BUN_REVISION
    with tempfile.TemporaryDirectory(prefix="merchant-proof-", dir=ROOT.parent / "tmp") as root:
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
        built = subprocess.run(  # noqa: S603 - checksum-verified compiler, owned diagnostic
            [
                str(bun),
                "build",
                "scripts/regtest-merchant.ts",
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
        assert built.returncode == 0, "merchant HTTPS diagnostic bundle refused"
        evidence = _run_two_node_sidecar(
            tmp_path,
            FUNDED_MERCHANT_PROOF,
            prefix="merchant-proof",
            deadline=300,
            profile="merchant_proof",
            merchant_bun_bundle=bundle,
            merchant_proof_tls_directory=tls,
        )
    assert evidence["agreed_amount_msat"] == 1000000
    for name in (
        "merchant_source_provenance",
        "single_ordinary_invoice",
        "single_payer_attempt",
        "merchant_history_unchanged",
        "private_inputs_unchanged",
    ):
        assert evidence[name] is True
