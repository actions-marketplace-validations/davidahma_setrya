"""Optional pytest fixture. Enable with -p setrya.pytest_plugin."""

import pytest

from .checker import Status
from .runner import run


@pytest.fixture
def setrya_check():
    def check(path, report=None):
        result = run(path)
        if report is not None:
            result.report.save(report)
        if result.verdict.status is not Status.PASS:
            pytest.fail(f"{result.verdict.status.label} · {result.verdict.detail}", pytrace=False)
        return result

    return check
