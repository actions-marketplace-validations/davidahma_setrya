"""Compatibility import for :mod:`setrya.core.subject`."""
import sys

from setrya.core import subject

sys.modules[__name__] = subject
