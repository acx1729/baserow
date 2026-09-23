import pytest

from baserow.contrib.database.action.scopes import TableActionScopeType
from baserow.contrib.database.field_rules.actions import (
    CreateFieldRuleActionType,
    DeleteFieldRuleActionType,
)
from baserow.contrib.database.field_rules.handlers import FieldRuleHandler
from baserow.contrib.database.field_rules.models import FieldRule
from baserow.core.action.handler import ActionHandler
from baserow.core.action.registries import action_type_registry


@pytest.mark.django_db
@pytest.mark.undo_redo
def test_can_undo_redo_creating_a_field_rule(data_fixture, fake_field_rule_registry):
    session_id = "session-id"
    user = data_fixture.create_user(session_id=session_id)
    table = data_fixture.create_database_table(user=user)
    scope = [TableActionScopeType.value(table.id)]

    rule = action_type_registry.get_by_type(CreateFieldRuleActionType).do(
        user, table, "dummy", {}
    )

    [undone] = ActionHandler.undo(user, scope, session_id)
    assert undone.error is None
    assert not FieldRule.objects.filter(id=rule.id).exists()

    [redone] = ActionHandler.redo(user, scope, session_id)
    assert redone.error is None
    # The rule is restored with the same id.
    assert FieldRule.objects.filter(id=rule.id, table=table).exists()


@pytest.mark.django_db
@pytest.mark.undo_redo
def test_can_undo_redo_deleting_a_field_rule(data_fixture, fake_field_rule_registry):
    session_id = "session-id"
    user = data_fixture.create_user(session_id=session_id)
    table = data_fixture.create_database_table(user=user)
    scope = [TableActionScopeType.value(table.id)]
    rule = FieldRuleHandler(table, user).create_rule("dummy", {"is_active": False})
    rule_id = rule.id

    action_type_registry.get_by_type(DeleteFieldRuleActionType).do(user, rule)
    assert not FieldRule.objects.filter(id=rule_id).exists()

    [undone] = ActionHandler.undo(user, scope, session_id)
    assert undone.error is None
    restored = FieldRule.objects.get(id=rule_id)
    assert restored.table_id == table.id
    assert restored.is_active is False

    [redone] = ActionHandler.redo(user, scope, session_id)
    assert redone.error is None
    assert not FieldRule.objects.filter(id=rule_id).exists()
