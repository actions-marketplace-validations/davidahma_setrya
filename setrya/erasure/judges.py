"""Compatibility import for :mod:`setrya.core.judges`."""
import sys

from setrya.core import judges

sys.modules[__name__] = judges
