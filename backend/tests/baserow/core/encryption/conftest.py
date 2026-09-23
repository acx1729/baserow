import json

from django.db import connection, models

import pytest


@pytest.fixture
def stored_value():
    """Returns a function that reads a value exactly as it's stored."""

    def get(model, field_name, pk):
        field = model._meta.get_field(field_name)
        with connection.cursor() as cursor:
            cursor.execute(
                f'SELECT "{field.column}" FROM "{model._meta.db_table}" '
                f'WHERE "{model._meta.pk.column}" = %s',
                [pk],
            )
            value = cursor.fetchone()[0]
        if isinstance(field, models.JSONField) and isinstance(value, str):
            value = json.loads(value)
        return value

    return get


@pytest.fixture
def store_raw_value():
    """
    Returns a function that writes a value without encrypting it, like the Baserow
    versions before encryption at rest did.
    """

    def store(model, field_name, pk, value):
        field = model._meta.get_field(field_name)
        with connection.cursor() as cursor:
            cursor.execute(
                f'UPDATE "{model._meta.db_table}" SET "{field.column}" = %s '
                f'WHERE "{model._meta.pk.column}" = %s',
                [value, pk],
            )

    return store
