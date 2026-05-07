"""
Exports normalized SecureOps events to the local filesystem.

v0 supports local file export only.
Future versions will add HTTP API forwarding to SecureOps.
"""

import json
import jsonschema
from datetime import datetime, timezone
from pathlib import Path


_SCHEMA_PATH = Path(__file__).parent.parent.parent / "schemas" / "event.schema.json"
_schema: dict | None = None


def _get_schema() -> dict:
    global _schema
    if _schema is None:
        with open(_SCHEMA_PATH) as f:
            _schema = json.load(f)
    return _schema


def validate(event: dict) -> None:
    """Validates an event against the SecureOps event schema. Raises on failure."""
    jsonschema.validate(instance=event, schema=_get_schema())


def export_local(events: list[dict], output_dir: Path, validate_schema: bool = True) -> list[Path]:
    """
    Writes each event as an individual JSON file and appends all events to a JSONL file.

    Returns a list of written file paths.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    jsonl_path = output_dir / f"{run_ts}_events.jsonl"

    written = []
    with open(jsonl_path, "w") as jsonl_file:
        for event in events:
            if validate_schema:
                try:
                    validate(event)
                except jsonschema.ValidationError as e:
                    print(f"[exporter] Schema validation failed for {event.get('event_id')}: {e.message}")
                    continue

            event_id = event.get("event_id", "unknown")
            event_path = output_dir / f"{run_ts}_{event_id}.json"
            with open(event_path, "w") as f:
                json.dump(event, f, indent=2, default=str)

            jsonl_file.write(json.dumps(event, default=str) + "\n")
            written.append(event_path)

    written.append(jsonl_path)
    return written


# TODO: implement when SecureOps HTTP API endpoint is available
def export_secureops_api(events: list[dict], endpoint: str, api_key: str) -> None:
    """
    Forwards normalized events to the SecureOps HTTP API.

    Not implemented in v0. Configure integrations.secureops in config.yaml to enable.
    """
    raise NotImplementedError(
        "SecureOps HTTP API integration is not implemented in v0. "
        "Use local export and ingest into SecureOps manually."
    )
