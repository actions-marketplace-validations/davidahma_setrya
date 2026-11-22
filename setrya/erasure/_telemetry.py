"""Connect optional OpenTelemetry carriers to the dependency-free provenance core."""

from setrya.core import journal, subject


def _baggage():
    from opentelemetry import baggage
    return baggage


def _span_event(name, attributes):
    from opentelemetry import trace
    trace.get_current_span().add_event(name, attributes)


def configure():
    subject._baggage_adapter = _baggage
    journal._trace_observer = _span_event
