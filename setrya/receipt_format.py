"""Compatibility import for :mod:`setrya.core.receipt_format`."""
import sys

from setrya.core import receipt_format

sys.modules[__name__] = receipt_format
