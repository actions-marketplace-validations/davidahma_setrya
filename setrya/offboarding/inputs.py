"""Compatibility import for :mod:`setrya.core.inputs`."""
import sys

from setrya.core import inputs

sys.modules[__name__] = inputs
