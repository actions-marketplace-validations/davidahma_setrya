# Test a deletion adapter

A Setrya direct adapter identifies the copies that belong to a subject, asks the store to delete them, and reads the store again. Both `find(subject)` and `verify_absent(subject)` return the **set of keys still present**. An empty set is meaningful only when the reader can see the relevant scope. Raise an error if the read is unavailable or incomplete.

The conformance kit takes a disposable adapter, two seeded subjects and the keys you expect to find. It deletes the target twice to check idempotency. After each delete it reads the retained subject through both methods. Run the example in a local Python interpreter after installing Setrya.

```python
import sqlite3
from contextlib import closing
from secrets import token_bytes

from setrya.erasure import Subject
from setrya.erasure.adapters import SQLiteAdapter
from setrya.erasure.conformance import check_erasure_adapter

secret = token_bytes(32)
removed = Subject.derive(secret, "test-tenant", "removed-user", "fixture")
retained = Subject.derive(secret, "test-tenant", "retained-user", "fixture")
with closing(sqlite3.connect(":memory:")) as db:
    db.execute("CREATE TABLE notes (id TEXT PRIMARY KEY, setrya_subject TEXT)")
    db.executemany("INSERT INTO notes VALUES (?, ?)",
                   [("note-a", removed.ref), ("note-b", retained.ref)])
    db.commit()
    check_erasure_adapter(SQLiteAdapter(db, "notes"),
                          subject=removed, retained=retained,
                          expected={"note-a"}, retained_expected={"note-b"})
```

Replace the adapter and seed operations with your store's implementation. Extend the test with its consistency, pagination and permissions behavior. To contribute a scanner, seed an untagged marker in the declared scope and the same marker outside it. Check the exact returned keys, then remove or hide the positive control and check that incomplete visibility cannot produce a clean verdict.

The conformance kit **executes deletion**. Production case verification uses the read-only observer. [Adapter requests](https://github.com/davidahma/setrya/issues/new?template=adapter.yml) · [Scanner requests](https://github.com/davidahma/setrya/issues/new?template=scanner.yml)

To exercise a supported backend and sign a replayable report, run the [vendor self-check](vendor-conformance.md).
