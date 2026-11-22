"""Compatibility import for :mod:`setrya.core.journal`."""
import sys

from setrya.core import journal

sys.modules[__name__] = journal
