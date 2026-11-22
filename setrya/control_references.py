"""Compatibility import for :mod:`setrya.core.control_references`."""
import sys

from setrya.core import control_references

sys.modules[__name__] = control_references
