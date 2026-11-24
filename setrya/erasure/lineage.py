"""Compatibility import for :mod:`setrya.core.lineage`."""
import sys

from setrya.core import lineage

sys.modules[__name__] = lineage
