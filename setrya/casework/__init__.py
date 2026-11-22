"""Read-only checks of completed deletion requests."""
from .observed import JournalObserver, observe_deletion

__all__ = ["JournalObserver", "observe_deletion"]
