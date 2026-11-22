"""Default storage declarations for the LangGraph PostgreSQL starter."""

STORES = """  checkpoints:
    kind: langgraph-checkpoint
    connection_env: SETRYA_TEST_POSTGRES_URL
    scope: ticket-204
    artifacts:
      ticket-204: delete  # The key must equal the exact thread ID given in scope.
  vectors:
    kind: postgres
    connection_env: SETRYA_TEST_POSTGRES_URL
    scope: ticket-204
    table: documents
    key_column: id
    content_column: body
    scope_column: ticket_id
    artifacts:
      document: delete
"""
CONTROL_STORED = ("    stored:\n      absent: [{memo: Harbor-17}]\n"
                  "      # Add the digest of the reviewed target-only test checkpoint.\n"
                  "      absent_sha256: []\n")
