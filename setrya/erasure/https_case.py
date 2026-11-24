"""Collect request-bound deployment facts from the TLS connection that serves a case."""

import json
import ssl
from contextlib import closing, contextmanager
from hashlib import sha256
from http.client import HTTPException, HTTPSConnection

from setrya.core.deployment import matches, valid_build


class DeploymentHTTP:
    def __init__(self, binding):
        self.record = binding["record"]
        self.origin = self.record["origin"]
        self.authority = self.origin.removeprefix("https://")
        self.context = ssl.create_default_context()
        self.evidence = {**binding, "reads": [], "erase": None}

    @contextmanager
    def request(self, method, route, payload, request_headers):
        """Use one verified socket for each credential and record the actual responder."""
        view = {"origin": self.origin, "tls_sha256": None, "build_id": None}
        if method == "DELETE":
            self.evidence["erase"] = view
        else:
            self.evidence["reads"].append(view)
        headers = request_headers()
        if method == "DELETE":
            headers["If-Match"] = f'"{self.record["build_id"]}"'
        with closing(HTTPSConnection(self.authority, timeout=10, context=self.context)) as connection:
            try:
                connection.connect()
                certificate = connection.sock.getpeercert(binary_form=True)
            except (OSError, HTTPException):
                yield None, False
                return
            if certificate:
                view["tls_sha256"] = sha256(certificate).hexdigest()
            if view["tls_sha256"] != self.record["tls_sha256"]:
                yield None, False
                return
            try:
                connection.request(method, route, body=json.dumps(payload).encode(), headers=headers)
                response = connection.getresponse()
            except (OSError, HTTPException):
                yield None, True
                return
            with closing(response):
                values = response.headers.get_all("X-Setrya-Build", ())
                if len(values) == 1 and valid_build(values[0]):
                    view["build_id"] = values[0]
                yield (response if matches(view, self.record) else None), True
