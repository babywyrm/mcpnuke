"""Base utilities for checks."""

import time

from mcprowler.core.models import TargetResult


def time_check(name: str, result: TargetResult):
    """Context manager to record check timing."""

    class _T:
        def __enter__(self):
            self.t0 = time.time()
            return self

        def __exit__(self, *_):
            result.timings[name] = time.time() - self.t0

    return _T()
