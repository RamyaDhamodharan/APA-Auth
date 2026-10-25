import json
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session


def record_audit(
    db: Session,
    *,
    action: str,
    entity_type: str,
    entity_id: UUID | None,
    result: str,
    message: str,
    created_by: UUID | None = None,
    old_value: dict | None = None,
    new_value: dict | None = None,
    output_summary: dict | None = None,
) -> None:
    """Write auth events to AP-Core's shared audit log without recording secrets."""
    db.execute(
        text(
            "INSERT INTO core.audit_log "
            "(action, entity_type, entity_id, old_value, new_value, result, "
            "message, output_summary, created_by) VALUES "
            "(:action, :entity_type, :entity_id, CAST(:old_value AS jsonb), "
            "CAST(:new_value AS jsonb), CAST(:result AS core.step_result), "
            ":message, CAST(:output_summary AS jsonb), :created_by)"
        ),
        {
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "old_value": json.dumps(old_value) if old_value is not None else None,
            "new_value": json.dumps(new_value) if new_value is not None else None,
            "result": result,
            "message": message,
            "output_summary": (
                json.dumps(output_summary) if output_summary is not None else None
            ),
            "created_by": created_by,
        },
    )
