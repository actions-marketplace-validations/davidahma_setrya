"""Compatibility import for :mod:`setrya.core.model`."""
import sys

from setrya.core import model

sys.modules[__name__] = model
