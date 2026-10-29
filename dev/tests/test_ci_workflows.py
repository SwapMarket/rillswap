"""CI action references remain immutable and consistent across workflows."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS = sorted((Path(__file__).resolve().parents[2] / ".github/workflows").glob("*.yml"))


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.stem)
def test_actions_use_immutable_versioned_references(workflow: Path) -> None:
    actions = re.findall(r"^\s+(?:- )?uses: (\S+)(.*)$", workflow.read_text(), re.M)
    assert actions
    for action, comment in actions:
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", action), action
        assert re.fullmatch(r" # v\d+\.\d+\.\d+", comment), action


def test_action_versions_are_consistent_across_workflows() -> None:
    references: dict[str, str] = {}
    for workflow in WORKFLOWS:
        for action, reference in re.findall(
            r"^\s+(?:- )?uses: ([\w./-]+)@(\S+)", workflow.read_text(), re.M
        ):
            assert references.setdefault(action, reference) == reference, action


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.stem)
def test_jobs_pin_the_ubuntu_image(workflow: Path) -> None:
    runners = re.findall(r"^\s+runs-on: (\S+)$", workflow.read_text(), re.M)
    assert runners
    assert set(runners) == {"ubuntu-26.04"}
