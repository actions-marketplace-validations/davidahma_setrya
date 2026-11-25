"""CLI spellings for the existing erasure evidence modes."""

CLI_MODES = ("deletion", "write-back", "late-write")


def evidence_mode(mode):
    """Keep the wire value shared by historical and new write-back runs."""
    return "late-write" if mode == "write-back" else mode
