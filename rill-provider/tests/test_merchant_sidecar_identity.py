"""Container-visible private fixture identity, without permission relaxation."""

import os
import subprocess
from pathlib import Path

import pytest
import test_lnd_payment_pinned as fixture


@pytest.mark.parametrize("owner", ["0:0", "1001:1001", "1000:1002"])
def test_sidecar_identity_uses_container_owner_and_private_tmpfs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, owner: str
) -> None:
    calls: list[tuple[str, ...]] = []

    def docker(*args: str, **_kwargs: object) -> str:
        calls.append(args)
        return owner

    monkeypatch.setattr(fixture, "_docker", docker)
    args = fixture._merchant_sidecar_identity(tmp_path)  # noqa: SLF001 - test-only helper
    uid, gid = owner.split(":")
    assert args == (
        "--user",
        owner,
        "--tmpfs",
        f"/tmp:rw,mode=0700,uid={uid},gid={gid},noexec,nosuid,nodev",  # noqa: S108 - test tmpfs
    )
    probe = calls[0]
    assert probe[probe.index("--network") + 1] == "none"
    assert probe[probe.index("--cap-drop") + 1] == "ALL"
    assert probe[probe.index("--security-opt") + 1] == "no-new-privileges"
    assert "--read-only" in probe
    assert f"type=bind,src={tmp_path},dst=/work/generated,readonly" in probe
    assert fixture.PYTHON_IMAGE in probe
    assert calls[1] == ("rm", "--force", probe[probe.index("--name") + 1])


@pytest.mark.parametrize(
    "owner",
    ["", "0", "0:0\n1:1", "-1:0", "root:root", "4294967295:0", "0:99999999999"],
)
def test_sidecar_identity_refuses_unbounded_or_non_numeric_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, owner: str
) -> None:
    monkeypatch.setattr(fixture, "_docker", lambda *_args, **_kwargs: owner)
    with pytest.raises(AssertionError, match="invalid private fixture ownership"):
        fixture._merchant_sidecar_identity(tmp_path)  # noqa: SLF001 - test-only helper


def test_sidecar_identity_removes_its_named_probe_after_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[str, ...]] = []

    def docker(*args: str, **kwargs: object) -> str:
        calls.append(args)
        if args[0] == "run":
            raise subprocess.TimeoutExpired("docker", 60)
        assert kwargs == {"check": False}
        return ""

    monkeypatch.setattr(fixture, "_docker", docker)
    with pytest.raises(subprocess.TimeoutExpired):
        fixture._merchant_sidecar_identity(tmp_path)  # noqa: SLF001 - test-only helper
    probe = calls[0][calls[0].index("--name") + 1]
    assert probe.startswith("rillswap-private-owner-")
    assert calls[1] == ("rm", "--force", probe)


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1" or fixture.DOCKER is None,
    reason="explicit isolated Docker opt-in required",
)
def test_capability_free_sidecar_reads_private_bind_as_its_mapped_owner(tmp_path: Path) -> None:
    generated = tmp_path / "generated"
    generated.mkdir(mode=0o700)
    original = fixture._merchant_sidecar_identity(generated)[1]  # noqa: SLF001 - test-only helper
    bind = f"type=bind,src={generated},dst=/work/generated"
    docker = fixture._docker  # noqa: SLF001 - isolated Docker fixture
    sandbox = ("--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges")
    try:
        docker(
            "run",
            "--rm",
            "--network",
            "none",
            "--mount",
            bind,
            fixture.PYTHON_IMAGE,
            "python",
            "-c",
            "import os; p='/work/generated'; f=p+'/walletunlocker_pb2.py'; "
            "open(f,'w').write('fixture_import = True\\n'); "
            "os.chmod(f,0o600); os.chown(f,1001,1001); os.chown(p,1001,1001)",
        )
        with pytest.raises(AssertionError, match="import=walletunlocker_pb2"):
            docker(
                "run",
                "--rm",
                "--network",
                "none",
                *sandbox,
                "--user",
                "0:0",
                "--mount",
                bind + ",readonly",
                "--env",
                "PYTHONPATH=/work/generated",
                fixture.PYTHON_IMAGE,
                "python",
                "-c",
                "import walletunlocker_pb2",
            )
        identity = fixture._merchant_sidecar_identity(generated)  # noqa: SLF001 - test-only helper
        assert identity[1] == "1001:1001"
        result = docker(
            "run",
            "--rm",
            "--network",
            "none",
            *sandbox,
            *identity,
            "--mount",
            bind + ",readonly",
            "--env",
            "PYTHONPATH=/work/generated",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            fixture.PYTHON_IMAGE,
            "python",
            "-c",
            "import os,tempfile,walletunlocker_pb2\n"
            "assert walletunlocker_pb2.fixture_import\n"
            "assert os.stat('/work/generated').st_mode & 0o777 == 0o700\n"
            "assert os.stat('/work/generated/walletunlocker_pb2.py').st_mode & 0o777 == 0o600\n"
            "with tempfile.TemporaryDirectory(dir='/tmp'): pass\n"
            "try: open('/work/generated/write-denied','w')\n"
            "except OSError: pass\n"
            "else: raise AssertionError('private bind must remain read-only')\n"
            "print('private access verified')",
        )
        assert result == "private access verified"
    finally:
        uid, gid = original.split(":")
        docker(
            "run",
            "--rm",
            "--network",
            "none",
            "--mount",
            bind,
            fixture.PYTHON_IMAGE,
            "python",
            "-c",
            f"import os; p='/work/generated'; os.chown(p,{uid},{gid}); "
            f"os.chown(p+'/walletunlocker_pb2.py',{uid},{gid})",
        )
