"""Opt-in funded merchant conformance, isolated to disposable regtest resources."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import selectors
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import test_lnd_payment_pinned as pinned
from test_lnd_payment_pinned import (
    CHANNEL_SETUP,
    ROOT,
    _assert_merchant_namespace,
    _merchant_fixture_mounts,
    _run_two_node_sidecar,
)

BUN_SHA256 = "6d5bb405b1d037a2a466b92757de7e47e4369930fa94bd42f8ff44ba49de6c57"
BUN_REVISION = "1.3.11+af24e281e"


def _controller_response(
    fd: int, selector: selectors.BaseSelector, buffer: bytearray, deadline: float
) -> dict[str, object]:
    while b"\n" not in buffer:
        remaining = deadline - time.monotonic()
        assert remaining > 0, "controller response timed out"
        assert selector.select(timeout=remaining), "controller response timed out"
        chunk = os.read(fd, 4096)
        assert chunk, "controller exited before response"
        buffer.extend(chunk)
        assert len(buffer) <= 65536, "controller response exceeds limit"
    raw, _, rest = buffer.partition(b"\n")
    buffer[:] = rest
    value = json.loads(raw)
    assert isinstance(value, dict), "invalid controller response shape"
    return value


BUN_MERCHANT = (
    "import json, os, selectors, time\n"
    + inspect.getsource(_controller_response)
    + CHANNEL_SETUP
    + """
    import selectors, subprocess
    print('PHASE: bun_merchant_provision', file=sys.stderr)
    private = Path('/tmp/bun-merchant')
    private.mkdir(mode=0o700)
    os.umask(0o077)
    (private / 'config.json').write_text(json.dumps({
        'origin': 'https://merchant.invalid', 'receiver': b_key}))
    for name in ('issuance.key', 'status.key', 'event.key'):
        (private / name).write_bytes(secrets.token_bytes(32))
    scoped_scenario = bool(globals().get('LEAST_PRIVILEGE_SCENARIO', False))
    def bake(permissions):
        value = call(b, b_secret, 'BakeMacaroon', ln.BakeMacaroonRequest,
            ln.BakeMacaroonResponse, ln.BakeMacaroonRequest(permissions=[
                ln.MacaroonPermission(entity=entity, action=action)
                for entity, action in permissions], root_key_id=0,
                allow_external_permissions=False)).macaroon
        credential = bytes.fromhex(value)
        assert 0 < len(credential) <= 4096
        return credential
    merchant_credential = b_secret
    if scoped_scenario:
        merchant_credential = bake([('info', 'read'), ('invoices', 'read'),
            ('invoices', 'write')])
        reader = bake([('info', 'read'), ('invoices', 'read')])
        assert merchant_credential != b_secret and reader != merchant_credential
        assert merchant_credential[-34:-32] == bytes([6, 32])
        invalid = bytearray(merchant_credential)
        invalid[-1] ^= 1  # Preserve the v2 packet structure, invalidate only signature.
        (private / 'reader.macaroon').write_bytes(reader)
        (private / 'invalid.macaroon').write_bytes(invalid)
        (private / 'probe.preimage').write_bytes(secrets.token_bytes(32))
    (private / 'macaroon').write_bytes(merchant_credential)
    (private / 'admin.token').write_text(secrets.token_urlsafe(32))
    (private / 'journal.json').write_text(json.dumps({'addCalls': 0}))
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(private),
        'RILLSWAP_DISPOSABLE_BUN_LND': '1'}
    child = None
    selector = None
    response_buffer = bytearray()
    def line():
        return _controller_response(child.stdout.fileno(), selector, response_buffer,
            time.monotonic() + 20)
    def start(mode):
        global child, selector
        child = subprocess.Popen(['/work/bun', '/work/merchant.js', mode], env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1)
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ)
        response_buffer.clear()
        ready = line()
        assert ready['ready'] is True
        return ready['publicKey']
    def command(action, **fields):
        child.stdin.write(json.dumps({'action': action, **fields}) + '\\n')
        child.stdin.flush()
        answer = line()
        assert answer['ok'] is True, 'Bun controller refused command'
        return answer.get('result')
    def stop(*, crash=False):
        global child, selector
        if child is None:
            return
        if child.poll() is None:
            if crash:
                child.kill()
            else:
                command('stop')
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
                raise AssertionError('owned Bun child failed to terminate') from None
        selector.close()
        for pipe in (child.stdin, child.stdout):
            pipe.close()
        child = None
    result = subprocess.run(['/work/bun', '/work/merchant.js', 'provision'], env=env,
        capture_output=True, text=True, timeout=20, check=False)
    assert result.returncode == 0, 'explicit merchant provision failed'
    assert json.loads(result.stdout)['provisioned'] is True
    try:
        pinned_key = start('issue_fault')
        created = command('http', path='/v1/intents', method='POST',
            key='bun_merchant_intent_01', body={'orderRef': 'bun-regtest-order',
                'amountMsat': '1000000', 'expiresAt': int(time.time()) + 3600})
        assert created['status'] == 201 and created['body']['status'] == 'waiting'
        intent = created['body']['id']
        token = created['body']['statusToken']
        route = '/v1/intents/' + intent
        unresolved = command('http', path=route + '/attempts', method='POST',
            key='bun_merchant_attempt_01', body={})
        assert unresolved['status'] == 202 and unresolved['body']['attempt'] is None
        identity_before = command('attempt', intentId=intent)
        assert identity_before['state'] == 'unknown'
        stop(crash=True)
        print('PHASE: bun_merchant_issuance_restart', file=sys.stderr)
        assert start('observe_fault') == pinned_key
        assert command('tick')['failedAttemptIds'] == []
        ready = command('http', path=route, token=token)
        assert ready['status'] == 200 and ready['body']['status'] == 'waiting'
        attempt = ready['body']['attempt']
        assert attempt['terms']['receiver'] == b_key
        assert attempt['terms']['network'] == 'regtest'
        assert attempt['terms']['amountMsat'] == '1000000'
        after = command('attempt', intentId=intent)
        assert after['id'] == identity_before['id']
        assert after['operationId'] == identity_before['operationId']
        assert after['state'] == 'ready'
        assert command('audit', intentId=intent)['addCalls'] == 1
        assert command('http', path=route + '/events', token=token)['body'] == []
        credential_evidence = {}
        if scoped_scenario:
            print('PHASE: bun_merchant_credentials', file=sys.stderr)
            probes = command('credentials', intentId=intent)
            assert probes == {'readInfo': True, 'readInvoice': True,
                'writeRefused': True, 'wrongCaRefused': True,
                'invalidSignatureRefused': True}
            import base64, socket, ssl
            tls = ssl.create_default_context(cafile='/work/public/b.cert')
            preimage = (private / 'probe.preimage').read_bytes()
            probe_hash = hashlib.sha256(preimage).hexdigest()
            with httpx.Client(base_url='https://127.0.0.1:8081', verify=tls,
                    headers={'Grpc-Metadata-macaroon': reader.hex()}, timeout=10,
                    trust_env=False, follow_redirects=False) as rest:
                denied = rest.post('/v1/invoices', json={
                    'r_preimage': base64.b64encode(preimage).decode(),
                    'value_msat': '1000', 'expiry': '600'})
                detail = denied.json()
                assert denied.status_code == 500 and detail.get('code') == 2
                assert 'permission denied' in str(detail.get('message', '')).lower()
                absent = rest.get('/v1/invoice/' + probe_hash)
                assert absent.status_code == 404 and absent.json().get('code') == 5
            print('PHASE: bun_merchant_invalid_signature', file=sys.stderr)
            with httpx.Client(base_url='https://127.0.0.1:8081', verify=tls,
                    headers={'Grpc-Metadata-macaroon': bytes(invalid).hex()}, timeout=10,
                    trust_env=False, follow_redirects=False) as rest:
                denied = rest.get('/v1/getinfo')
                detail = denied.json()
                assert denied.status_code == 500 and detail.get('code') == 2
                assert 'signature mismatch' in str(detail.get('message', '')).lower()
            print('PHASE: bun_merchant_wrong_ca', file=sys.stderr)
            foreign_ca = ssl.create_default_context(cafile='/work/public/a.cert')
            try:
                with socket.create_connection(('127.0.0.1', 8081), timeout=5) as sock:
                    with foreign_ca.wrap_socket(sock, server_hostname='127.0.0.1'):
                        raise AssertionError('foreign CA unexpectedly trusted')
            except ssl.SSLCertVerificationError:
                pass
            print('PHASE: bun_merchant_spending_denied', file=sys.stderr)
            # Test on b, whose scoped macaroon this is. No invoice or destination.
            spending = b.unary_stream('/routerrpc.Router/SendPaymentV2',
                request_serializer=router.SendPaymentRequest.SerializeToString,
                response_deserializer=ln.Payment.FromString)
            try:
                list(spending(router.SendPaymentRequest(),
                    metadata=metadata(merchant_credential), timeout=5))
            except grpc.RpcError as error:
                assert error.code() == grpc.StatusCode.UNKNOWN
                assert 'permission denied' in (error.details() or '').lower()
            else:
                raise AssertionError('scoped credential unexpectedly allows SendPaymentV2')
            credential_evidence = {'scoped_permissions_sufficient': True,
                'readonly_write_denied': True, 'probe_hash_absent': True,
                'wrong_ca_rejected': True, 'invalid_signature_rejected': True,
                'send_payment_rpc_denied': True}
        forged = command('http', path=route + '/evidence', method='POST', token=token,
            body={'accepted': True, 'preimage': '00' * 32})
        assert forged['status'] == 202 and forged['body']['accepted'] is False
        print('PHASE: bun_merchant_pay_once', file=sys.stderr)
        channel_id = views[0][0].chan_id
        # Active channel is not proof that the payer's routing view is ready.
        for _ in range(100):
            try:
                available = call(a, a_secret, 'QueryRoutes', ln.QueryRoutesRequest,
                    ln.QueryRoutesResponse, ln.QueryRoutesRequest(pub_key=b_key,
                        amt_msat=1000000, final_cltv_delta=40,
                        outgoing_chan_ids=[channel_id], fee_limit=ln.FeeLimit(fixed_msat=0),
                        use_mission_control=False), timeout=2)
                if (available.routes and len(available.routes[0].hops) == 1
                        and available.routes[0].hops[0].chan_id == channel_id
                        and available.routes[0].total_amt_msat == 1000000):
                    break
            except grpc.RpcError:
                pass
            time.sleep(0.2)
        else:
            print('DIAGNOSTIC: route_unavailable', file=sys.stderr)
            raise AssertionError('exact direct payer route not ready')
        send = a.unary_stream('/routerrpc.Router/SendPaymentV2',
            request_serializer=router.SendPaymentRequest.SerializeToString,
            response_deserializer=ln.Payment.FromString)
        sending = send(router.SendPaymentRequest(payment_request=attempt['invoice'],
            max_parts=1, outgoing_chan_ids=[channel_id], no_inflight_updates=False,
            fee_limit_msat=0, timeout_seconds=30), metadata=metadata(a_secret), timeout=60)
        succeeded = None
        for payment in sending:
            assert payment.payment_hash == attempt['terms']['paymentHash']
            if payment.status == ln.Payment.SUCCEEDED:
                succeeded = payment
                break
            if payment.status == ln.Payment.FAILED:
                print('DIAGNOSTIC: payment_failed_' + str(payment.failure_reason),
                    file=sys.stderr)
            assert payment.status != ln.Payment.FAILED
        print('PHASE: bun_merchant_payment_result', file=sys.stderr)
        assert succeeded is not None
        assert succeeded.value_msat == 1000000 and succeeded.fee_msat == 0
        assert len(succeeded.htlcs) == 1
        htlc = succeeded.htlcs[0]
        print('PHASE: bun_merchant_exact_htlc', file=sys.stderr)
        assert htlc.status == ln.HTLCAttempt.SUCCEEDED
        assert len(htlc.route.hops) == 1
        assert htlc.route.hops[0].pub_key == b_key
        assert htlc.route.hops[0].chan_id == channel_id
        assert htlc.route.hops[0].amt_to_forward_msat == 1000000
        sending.cancel()
        print('PHASE: bun_merchant_receipt_restart', file=sys.stderr)
        failed = command('tick')['failedAttemptIds']
        assert failed == [identity_before['id']]
        assert command('http', path=route, token=token)['body']['status'] == 'waiting'
        assert command('http', path=route + '/events', token=token)['body'] == []
        stop(crash=True)
        assert start('normal') == pinned_key
        assert command('tick')['failedAttemptIds'] == []
        paid = command('http', path=route, token=token)
        assert paid['body']['status'] == 'paid'
        assert paid['body']['attempt'] == attempt
        events = command('http', path=route + '/events', token=token)['body']
        assert len(events) == 1 and events[0]['publicKey'] == pinned_key
        event = events[0]['event']
        assert event['type'] == 'payment.accepted' and event['amountMsat'] == '1000000'
        assert event['paymentHash'] == attempt['terms']['paymentHash']
        assert command('verify', body=events)['valid'] is True
        assert command('tick')['failedAttemptIds'] == []
        assert command('http', path=route + '/events', token=token)['body'] == events
        lost = command('deliver', fail=True)
        assert lost['delivered'] == events and lost['pending'] == 1
        stop(crash=True)
        print('PHASE: bun_merchant_event_restart', file=sys.stderr)
        assert start('normal') == pinned_key
        delivered = command('deliver', fail=False)
        assert delivered['delivered'] == events and delivered['pending'] == 0
        assert command('deliver', fail=False)['delivered'] == []
        assert command('http', path=route + '/events', token=token)['body'] == events
        audited = command('audit', intentId=intent)
        assert audited == {'addCalls': 1, 'pending': 0, 'events': 1,
            'secretFree': True, 'identityStable': True}
        print(json.dumps({'funding_txid': txid, 'vout': point.output_index,
            'capacity_sat': views[0][0].capacity, 'bun_lnd_checkout': True,
            'issuance_restart_same_operation': True, 'receipt_restart_once': True,
            'event_restart_same_id': True, 'secret_free': True,
            'invoice_dispatches': audited['addCalls'], 'payer_htlcs': len(succeeded.htlcs),
            'merchant_received_msat': succeeded.value_msat, **credential_evidence}))
    finally:
        stop(crash=True)
"""
)


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1" or os.environ.get("RILLSWAP_RUN_BUN_MERCHANT") != "1",
    reason="set RILLSWAP_RUN_LND=1 and RILLSWAP_RUN_BUN_MERCHANT=1 for funded Bun conformance",
)
def test_pinned_bun_merchant_checkout_restart(tmp_path: Path) -> None:
    """Use actual TLS/macaroons, invoice settlement and merchant journal restarts."""
    evidence = _run_bun_fixture(tmp_path, BUN_MERCHANT)
    for field in (
        "bun_lnd_checkout",
        "issuance_restart_same_operation",
        "receipt_restart_once",
        "event_restart_same_id",
        "secret_free",
    ):
        assert evidence[field] is True
    assert evidence["invoice_dispatches"] == evidence["payer_htlcs"] == 1
    assert evidence["merchant_received_msat"] == 1_000_000


def _run_bun_fixture(tmp_path: Path, program: str) -> dict[str, object]:
    bun = ROOT.parent / "tmp/toolchains/bun-v1.3.11/bun"
    assert hashlib.sha256(bun.read_bytes()).hexdigest() == BUN_SHA256
    revision = subprocess.run(  # noqa: S603 - digest-verified pinned executable
        [str(bun), "--revision"], capture_output=True, text=True, timeout=5, check=True
    )
    assert revision.stdout.strip() == BUN_REVISION
    local_tmp = ROOT.parent / "tmp"
    local_tmp.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="bun-merchant-", dir=local_tmp) as directory:
        bundle = Path(directory) / "merchant.js"
        built = subprocess.run(  # noqa: S603 - pinned compiler and repository-owned test fixture
            [
                str(bun),
                "build",
                "tests/fixtures/merchantLndHarness.ts",
                "--target",
                "bun",
                "--outfile",
                str(bundle),
            ],
            cwd=ROOT.parent / "rill-payments",
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert built.returncode == 0, "merchant fixture bundle failed to build"
        return _run_two_node_sidecar(
            tmp_path,
            program,
            prefix="bun-merchant",
            deadline=300,
            profile="merchant_receipt",
            merchant_bun_bundle=bundle,
        )


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1" or os.environ.get("RILLSWAP_RUN_BUN_MERCHANT") != "1",
    reason="set both opt-in flags for scoped merchant credential conformance",
)
def test_pinned_bun_merchant_scoped_credentials(tmp_path: Path) -> None:
    """Documented permissions suffice; rejected probes cannot create an invoice."""
    evidence = _run_bun_fixture(tmp_path, "LEAST_PRIVILEGE_SCENARIO = True\n" + BUN_MERCHANT)
    for field in (
        "bun_lnd_checkout",
        "issuance_restart_same_operation",
        "receipt_restart_once",
        "event_restart_same_id",
        "secret_free",
        "scoped_permissions_sufficient",
        "readonly_write_denied",
        "probe_hash_absent",
        "wrong_ca_rejected",
        "invalid_signature_rejected",
        "send_payment_rpc_denied",
    ):
        assert evidence[field] is True
    assert evidence["invoice_dispatches"] == evidence["payer_htlcs"] == 1
    assert evidence["merchant_received_msat"] == 1_000_000


def test_bun_fixture_mount_rejects_untrusted_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative mount checks require neither Docker nor the downloaded toolchain."""
    assert _merchant_fixture_mounts("baseline", None) == ()
    with pytest.raises(ValueError, match="isolated merchant"):
        _merchant_fixture_mounts("baseline", tmp_path / "fixture.js")
    root = tmp_path / "repo"
    binary = root / "tmp/toolchains/bun-v1.3.11/bun"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"wrong executable")
    monkeypatch.setattr(pinned, "ROOT", root / "rill-provider")
    foreign = tmp_path / "foreign.js"
    foreign.write_text("untrusted")
    with pytest.raises(ValueError, match="repository-local"):
        _merchant_fixture_mounts("merchant_receipt", foreign)
    bundle = root / "tmp/fixture.js"
    bundle.write_text("fixture")
    with pytest.raises(ValueError, match="checksum"):
        _merchant_fixture_mounts("merchant_receipt", bundle)
    binary.unlink()
    binary.symlink_to(foreign)
    with pytest.raises(ValueError, match="regular source"):
        _merchant_fixture_mounts("merchant_receipt", bundle)


def test_controller_partial_line_obeys_response_deadline() -> None:
    read_fd, write_fd = os.pipe()
    selector = selectors.DefaultSelector()
    try:
        selector.register(read_fd, selectors.EVENT_READ)
        os.write(write_fd, b'{"ok":')
        buffer = bytearray()
        with pytest.raises(AssertionError, match="timed out"):
            _controller_response(read_fd, selector, buffer, time.monotonic() + 0.05)
        os.write(write_fd, b"true}\n")
        assert _controller_response(read_fd, selector, buffer, time.monotonic() + 1) == {"ok": True}
    finally:
        selector.close()
        os.close(read_fd)
        os.close(write_fd)


def test_namespace_checks_reject_external_network_and_host_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for violation in ("network", "ports"):

        def docker(*args: str, case: str = violation) -> str:
            if args[-1] == "{{.Id}}":
                return "owned-core-id"
            name = args[1]
            return json.dumps(
                {
                    "NetworkMode": "none"
                    if name == "core"
                    else ("bridge" if case == "network" else "container:owned-core-id"),
                    "PortBindings": {"8081/tcp": [{"HostPort": "8081"}]} if case == "ports" else {},
                }
            )

        monkeypatch.setattr(pinned, "_docker", docker)
        with pytest.raises(AssertionError):
            _assert_merchant_namespace("core", ("a", "b"))
