"""Original SDK death after signed fallback acknowledgment, explicit recovery only.

The accepted pre-signer scenario remains unchanged. This separate scenario uses
the actual SDK publisher and original custody, not a replacement SDK invocation.
Manual recovery re-signs; its broadcast must match its own verified plan, not the
SDK fallback's signature bytes or transaction ID.
"""

from __future__ import annotations

import ast
import os
from importlib import import_module
from typing import TYPE_CHECKING, Any

import pytest
import test_merchant_sdk_death_pinned as original

if TYPE_CHECKING:
    from pathlib import Path

# Embedded owned programs are compiled and checked structurally offline.
# ruff: noqa: E501


def _replace_once(document: str, before: str, after: str) -> str:
    assert document.count(before) == 1, "owned SDK boundary template changed"
    return document.replace(before, after, 1)


SIGNING_BOUNDARY = r"""    signer_acquisitions=0
    local_signatures=0
    original_signer=live_reverse_swap._claim_signer
    def counted_signer(*args,**kwargs):
        global signer_acquisitions
        signer_acquisitions+=1
        assert signer_acquisitions==1
        sign,ceiling=original_signer(*args,**kwargs)
        def counted_sign(fee,tip):
            global local_signatures
            local_signatures+=1
            return sign(fee,tip)
        return counted_sign,ceiling
    live_reverse_swap._claim_signer=counted_signer
    original_publish=live_reverse_swap._publish_reverse_fallback
    async def acknowledged_fallback(*args,**kwargs):
        snapshot=await original_publish(*args,**kwargs)
        assert isinstance(snapshot,bytes)
        assert json.loads(snapshot)['extensions']['rillswap/reverse-claim-fallback']['version']==1
        assert signer_acquisitions==1 and local_signatures==1
        print('FALLBACK_READY',flush=True)
        assert sys.stdin.buffer.read(1)==b'1'
        print('FALLBACK_ACK',flush=True)
        # Parent has independently read and native-validated the actual saved
        # artifact. Never return into cooperation, disclosure or SDK watchers.
        threading.Event().wait()
        raise AssertionError('original fallback boundary unexpectedly returned')
    live_reverse_swap._publish_reverse_fallback=acknowledged_fallback
    async def no_cooperation(*args,**kwargs):
        print('COOPERATION_TRIPWIRE',flush=True)
        raise AssertionError('original SDK must not enter cooperation')
    live_reverse_swap._cooperative_claim=no_cooperation
"""


def _child() -> str:
    child = _replace_once(
        original.SDK_CHILD,
        """    def no_signer(*args,**kwargs):
        print('SIGNER_TRIPWIRE',flush=True)
        raise AssertionError('original SDK must not acquire its claim signer')
    live_reverse_swap._claim_signer=no_signer
""",
        SIGNING_BOUNDARY,
    )
    return _replace_once(
        child,
        """            # Only the parent-owned kill terminates this test boundary. Never
            # return success into signing, even if stdin closes unexpectedly.
            threading.Event().wait()
""",
        """            # Funding capture is acknowledged before actual local signing.
            return None
""",
    )


SDK_CHILD = _child()

FALLBACK_READBACK = r"""                await marker(b'FALLBACK_READY\n',15)
                # Do not acquire the child's journal owner while it is alive.
                # Read only the three explicitly named retained custody files.
                ack_initial=directory/'inventory'/'recovery'/'owned_treasury_reverse_01.age'
                ack_funded=ack_initial.with_suffix('.age.funded')
                ack_fallback=ack_initial.with_suffix('.age.fallback')
                ack_initial_plain=decrypt_verified_plaintext(_read_private(ack_initial,262144),authority.network,credentials=credentials,crypto=crypto)
                ack_funded_plain=decrypt_verified_plaintext(_read_private(ack_funded,262144),authority.network,credentials=credentials,crypto=crypto)
                ack_cipher=_read_private(ack_fallback,262144)
                ack_plain=decrypt_verified_plaintext(ack_cipher,authority.network,credentials=credentials,crypto=crypto)
                inspect_recovery_successor(ack_initial_plain,ack_funded_plain,authority.network,crypto=crypto)
                inspect_recovery_successor(ack_funded_plain,ack_plain,authority.network,crypto=crypto)
                ack_value=json.loads(ack_plain)
                assert ack_value['monotonic_knowledge']['dangerous_signature_issued'] is False
                assert len(ack_value['funding_history'])==1
                ack_binding=FundingBinding.model_validate(ack_value['funding_history'][0]['binding'])
                ack_selected=inspect_recovery_selected_funding_context(ack_plain,authority.network,
                    funding_attempt_id=ack_binding.funding_attempt_id,binding_revision=ack_binding.binding_revision,crypto=crypto)
                assert ack_selected.binding==ack_binding
                from rill_core.wire.hashes import funding_binding_hash
                ack_marker=ack_value['extensions']['rillswap/reverse-claim-fallback']
                assert set(ack_marker)=={'version','funding_binding_hash','transaction'}
                assert ack_marker['version']==1 and ack_marker['funding_binding_hash']==funding_binding_hash(ack_binding).hex()
                ack_authorization=UnilateralAuthorization.from_terms(ack_selected.terms,
                    FundingOutput(bytes.fromhex(ack_binding.funding_txid),ack_binding.contract_vout,
                        int(ack_binding.contract_value_sat),bytes.fromhex(ack_binding.contract_script_pubkey)),
                    'claim',keys=crypto)
                ack_spend=validate_unilateral_spend(bytes.fromhex(ack_marker['transaction']),ack_authorization,verifier=crypto)
                assert 0<ack_spend.fee_sat<=int(ack_selected.terms.max_claim_fee_sat)
                fallback_artifacts=immutable((ack_initial,ack_funded,ack_fallback))
                child.stdin.write(b'1')
                await child.stdin.drain()
                await marker(b'FALLBACK_ACK\n',15)
"""

FALLBACK_SELECTION = r"""                funded_candidate=candidate
                funded_plaintext=plaintext
                assert immutable((initial,funded_candidate,ack_fallback))==fallback_artifacts
                assert _read_private(ack_fallback,262144)==ack_cipher
                candidate=ack_fallback
                plaintext=decrypt_verified_plaintext(_read_private(candidate,262144),authority.network,credentials=credentials,crypto=crypto)
                inspect_recovery_successor(funded_plaintext,plaintext,authority.network,crypto=crypto)
                assert plaintext==ack_plain
                funded_value=json.loads(funded_plaintext)
                fallback_value=json.loads(plaintext)
                assert fallback_value['funding_history']==funded_value['funding_history']
                assert fallback_value['monotonic_knowledge']==funded_value['monotonic_knowledge']
                assert fallback_value['user_secret']==funded_value['user_secret']
                recovery=json.loads(plaintext)
"""


def _program() -> str:
    program = _replace_once(
        original._program(),  # noqa: SLF001 - accepted owned template, never alter the original scenario
        f"    SDK_DEATH_CHILD = {original.SDK_CHILD!r}\n",
        f"    SDK_DEATH_CHILD = {SDK_CHILD!r}\n",
    )
    program = _replace_once(
        program,
        "                await marker(b'FUNDING_ACK\\n',15)\n",
        "                await marker(b'FUNDING_ACK\\n',15)\n" + FALLBACK_READBACK,
    )
    program = _replace_once(
        program, "                recovery=json.loads(plaintext)\n", FALLBACK_SELECTION
    )
    # Conversion admission requires a direct successor of the original journal
    # checkpoint. Fallback insertion instead follows the funded snapshot. Keep
    # those joins separate; manual recovery still consumes the actual fallback.
    program = _replace_once(
        program,
        "                    funding_recovery_path=candidate,funding_attempt_id=",
        "                    funding_recovery_path=funded_candidate,funding_attempt_id=",
    )
    program = _replace_once(
        program,
        "completed=await cli_completion(journal,authority,config,credentials,candidate,binding.model_dump",
        "completed=await cli_completion(journal,authority,config,credentials,funded_candidate,binding.model_dump",
    )
    program = _replace_once(
        program,
        "                assert immutable((identity,network,plan,intent))==manual_protected\n",
        "                assert immutable((identity,network,plan,intent))==manual_protected\n"
        "                assert immutable((initial,funded_candidate,candidate))==fallback_artifacts\n"
        "                assert ack_selected.binding==binding and ack_selected.terms==terms\n",
    )
    program = _replace_once(
        program,
        "                assert actual.txid==checked.claim_txid and actual.fee_sat==fee\n",
        "                assert actual.txid==checked.claim_txid and actual.fee_sat==fee\n"
        "                # Explicit regtest operator already created the disclosure intent\n"
        "                # and submitted the plan. Compare privately, never print witnesses.\n"
        "                from rill_cli.claim_plan import load_verified_claim_bytes_for_regtest_disclosure\n"
        "                planned_raw,planned_receipt=load_verified_claim_bytes_for_regtest_disclosure(\n"
        "                    _read_private(plan,262144),_read_private(candidate,262144),authority.network,\n"
        "                    credentials=credentials,funding_attempt_id=binding.funding_attempt_id,\n"
        "                    binding_revision=binding.binding_revision,crypto=crypto)\n"
        "                assert planned_receipt==checked\n"
        "                assert raw==planned_raw\n",
    )
    program = _replace_once(
        program,
        "original_sdk_claim_signer_acquired=False)",
        "original_sdk_claim_signer_acquired=True,original_sdk_signed_fallback_ack=True,"
        "original_sdk_signer_acquisitions=1,original_sdk_local_signatures=1)",
    )
    return _replace_once(
        program,
        "original_sdk_killed_before_claim_signer",
        "original_sdk_killed_after_signed_fallback_ack",
    )


def test_fallback_death_program_preserves_original_owner_and_two_acknowledgments() -> None:
    compile(SDK_CHILD, "<original-fallback-sdk-child>", "exec")
    program = _program()
    compile(program, "<original-fallback-sdk-death>", "exec")
    tree = ast.parse(program)
    child = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "SDK_DEATH_CHILD"
            for target in node.targets
        )
    ]
    assert len(child) == 1
    assert ast.literal_eval(child[0].value) == SDK_CHILD
    parents = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "funded_reverse"
    ]
    assert len(parents) == 1
    parent = ast.get_source_segment(program, parents[0])
    assert parent is not None
    funding = parent.index("await marker(b'FUNDING_ACK\\n',15)")
    ready = parent.index("await marker(b'FALLBACK_READY\\n',15)")
    proof = parent.index("ack_spend=validate_unilateral_spend")
    acknowledgment = parent.index("await marker(b'FALLBACK_ACK\\n',15)")
    # The shared parent also owns a separate public-CLI subprocess helper with
    # its own timeout kill. Check the SDK's exact ACK-adjacent kill, not that
    # unrelated nested helper's earlier lexical occurrence.
    sdk_kill = "await marker(b'FALLBACK_ACK\\n',15)\n                child.kill()"
    assert parent.count(sdk_kill) == 1
    killed = parent.index("child.kill()", acknowledgment)
    assert funding < ready < proof < acknowledgment < killed
    assert "original_sdk_claim_signer_acquired=False" not in program
    assert "await original_publish(*args,**kwargs)" in SDK_CHILD
    assert "signer_acquisitions==1 and local_signatures==1" in SDK_CHILD
    assert "live_reverse_swap._cooperative_claim=no_cooperation" in SDK_CHILD
    assert "assert raw==planned_raw" in parent
    assert "funding_recovery_path=funded_candidate" in parent
    assert "cli_completion(journal,authority,config,credentials,funded_candidate" in parent
    assert "'--output',str(plan),str(candidate)" in parent
    assert "'--acknowledge-regtest-preimage-disclosure',str(candidate)" in parent


def test_fallback_template_changes_refuse_instead_of_selecting_another_boundary() -> None:
    with pytest.raises(AssertionError, match="template changed"):
        _replace_once("not the original boundary", "missing", "replacement")
    with pytest.raises(AssertionError, match="template changed"):
        _replace_once("duplicate duplicate", "duplicate", "replacement")


@pytest.mark.lnd
@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1" or os.environ.get("RILLSWAP_RUN_BUN_MERCHANT") != "1",
    reason="explicit original SDK signed-fallback death and manual recovery opt-ins",
)
def test_pinned_original_sdk_death_after_signed_fallback_recovers_with_original_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = import_module("test_merchant_conversion_pinned")
    program = _program()

    def selected(**controls: Any) -> str:  # noqa: ANN401 - reuse the unchanged controlled owned launcher
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
    evidence = fixture._funded_evidence(  # noqa: SLF001 - unchanged owned setup, native/financial assertions and cleanup
        tmp_path,
        completion=True,
        cli_completion=True,
        retain_funding_inclusion=True,
        saved_cli_completion=True,
    )
    assert evidence["original_sdk_sigkilled"] is True
    assert evidence["original_key_manual_recovery"] is True
    assert evidence["original_sdk_claim_signer_acquired"] is True
    assert evidence["original_sdk_signed_fallback_ack"] is True
    assert evidence["original_sdk_signer_acquisitions"] == 1
    assert evidence["original_sdk_local_signatures"] == 1  # the prepared fallback only
    assert evidence["saved_operator_cli_completion"] is True
    assert evidence["original_claim_path"] == "unilateral"
