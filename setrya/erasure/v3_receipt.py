"""Compatibility import for :mod:`setrya.core.receipt_v3`."""
import sys

from setrya.core import receipt_v3

sys.modules[__name__] = receipt_v3
