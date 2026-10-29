"""Disposable image builds select their intended package and copy behavior."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "dockerfile", ["dev/Dockerfile", "dev/monero/Dockerfile", "rill-provider/docker/Dockerfile"]
)
def test_package_installs_select_noninteractive_debconf_only_for_the_command(
    dockerfile: str,
) -> None:
    source = (ROOT / dockerfile).read_text()
    installs = re.findall(r"^.*apt-get install.*$", source, re.M)
    assert installs
    assert all("DEBIAN_FRONTEND=noninteractive apt-get install" in line for line in installs)
    assert not re.search(r"^ENV.*DEBIAN_FRONTEND", source, re.M)


@pytest.mark.parametrize("dockerfile", ["dev/Dockerfile", "rill-provider/docker/Dockerfile"])
def test_native_builders_install_the_c_toolchain_without_packaging_tools(dockerfile: str) -> None:
    source = (ROOT / dockerfile).read_text()
    assert "gcc libc6-dev make cmake" in source
    assert "build-essential" not in source  # dpkg-dev would pull unused xz man-page alternatives


def test_dev_install_copies_across_the_buildkit_cache_mount() -> None:
    source = (ROOT / "dev/Dockerfile").read_text()
    assert "--mount=type=cache,target=/root/.cache/uv" in source
    assert "uv pip install --link-mode=copy" in source


def test_compose_ci_builds_shared_images_before_starting_consumers() -> None:
    source = (ROOT / ".github/workflows/compose-e2e.yml").read_text()
    assert re.search(r"docker compose build\s+docker compose up -d --no-build", source)
    manual = (ROOT / ".github/workflows/component-checks.yml").read_text()
    assert re.search(r"docker compose -f dev/compose.yaml build\s+dev/devctl up", manual)
