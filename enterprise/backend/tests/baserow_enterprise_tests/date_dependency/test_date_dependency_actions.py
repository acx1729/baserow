import pytest

from baserow.contrib.database.action.scopes import TableActionScopeType
from baserow.contrib.database.field_rules.actions import (
    CreateFieldRuleActionType,
    DeleteFieldRuleActionType,
)
from baserow.core.action.handler import ActionHandler
from baserow.core.action.registries import action_type_registry
from baserow_enterprise.date_dependency.models import DateDependency


def create_date_dependency_payload(data_fixture, table):
    return {
        "is_active": True,
        "start_date_field_id": data_fixture.create_date_field(table=table).id,
        "end_date_field_id": data_fixture.create_date_field(table=table).id,
        "duration_field_id": data_fixture.create_duration_field(
            table=table, duration_format="d h"
        ).id,
    }


@pytest.mark.django_db
@pytest.mark.undo_redo
def test_can_undo_redo_creating_a_date_dependency(data_fixture, enable_enterprise):
    session_id = "session-id"
    user = data_fixture.create_user(session_id=session_id)
    table = data_fixture.create_database_table(user=user)
    scope = [TableActionScopeType.value(table.id)]
    payload = create_date_dependency_payload(data_fixture, table)

    rule = action_type_registry.get_by_type(CreateFieldRuleActionType).do(
        user, table, "date_dependency", payload
    )

    [undone] = ActionHandler.undo(user, scope, session_id)
    assert undone.error is None
    assert not DateDependency.objects.filter(id=rule.id).exists()

    [redone] = ActionHandler.redo(user, scope, session_id)
    assert redone.error is None
    restored = DateDependency.objects.get(id=rule.id)
    assert restored.start_date_field_id == payload["start_date_field_id"]
    assert restored.end_date_field_id == payload["end_date_field_id"]
    assert restored.duration_field_id == payload["duration_field_id"]


@pytest.mark.django_db
@pytest.mark.undo_redo
def test_can_undo_redo_deleting_a_date_dependency(data_fixture, enable_enterprise):
    session_id = "session-id"
    user = data_fixture.create_user(session_id=session_id)
    table = data_fixture.create_database_table(user=user)
    scope = [TableActionScopeType.value(table.id)]
    payload = create_date_dependency_payload(data_fixture, table)
    rule = action_type_registry.get_by_type(CreateFieldRuleActionType).do(
        user, table, "date_dependency", payload
    )

    rule_id = rule.id

    action_type_registry.get_by_type(DeleteFieldRuleActionType).do(user, rule)
    assert not DateDependency.objects.filter(id=rule_id).exists()

    [undone] = ActionHandler.undo(user, scope, session_id)
    assert undone.error is None
    restored = DateDependency.objects.get(id=rule_id)
    assert restored.start_date_field_id == payload["start_date_field_id"]
    assert restored.duration_field_id == payload["duration_field_id"]

    [redone] = ActionHandler.redo(user, scope, session_id)
    assert redone.error is None
    assert not DateDependency.objects.filter(id=rule_id).exists()
