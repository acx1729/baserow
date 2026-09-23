from typing import Optional

from django.db import migrations


def column_exists(schema_editor, table_name: str, column_name: str) -> bool:
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        return column_name in {
            column.name
            for column in connection.introspection.get_table_description(
                cursor, table_name
            )
        }


class AddFieldIfNotExists(migrations.AddField):
    """
    Adds a field, unless its column already exists because a Baserow version with
    another migration history added it, e.g. a release that encryption at rest was
    backported to. Upgrading from that version must not fail, and must not run
    `sql_after_adding` again.

    :param sql_after_adding: SQL that only runs when the column is added, e.g. to
        initialize its value.
    """

    def __init__(self, *args, sql_after_adding: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.sql_after_adding = sql_after_adding

    def deconstruct(self):
        name, args, kwargs = super().deconstruct()
        if self.sql_after_adding:
            kwargs["sql_after_adding"] = self.sql_after_adding
        return name, args, kwargs

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        to_model = to_state.apps.get_model(app_label, self.model_name)
        if not self.allow_migrate_model(schema_editor.connection.alias, to_model):
            return

        field = to_model._meta.get_field(self.name)
        if column_exists(schema_editor, to_model._meta.db_table, field.column):
            return

        super().database_forwards(app_label, schema_editor, from_state, to_state)
        if self.sql_after_adding:
            schema_editor.execute(self.sql_after_adding)
