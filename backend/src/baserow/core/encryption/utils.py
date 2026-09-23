from django.db import models
from django.db.models.functions import Cast

from .handler import EncryptionHandler


def get_by_lookup_hash(
    queryset: models.QuerySet,
    value: str,
    field_name: str = "key",
    hash_field_name: str = "key_hash",
) -> models.Model:
    """
    Returns the object whose encrypted `field_name` equals `value`, by comparing the
    lookup hash stored in `hash_field_name`.

    Rows created by the previous Baserow version during a rolling upgrade don't have
    a hash yet, but their value is still in plain text. Those are matched on the
    plain text value and get their hash stored.

    :param queryset: The queryset to find the object in.
    :param value: The plain text value to look for, e.g. an API token.
    :param field_name: The name of the encrypted field.
    :param hash_field_name: The name of the field containing the lookup hash.
    :raises queryset.model.DoesNotExist: When no object matches the value.
    :return: The matching object.
    """

    value_hash = EncryptionHandler.hash_for_lookup(value)
    try:
        return queryset.get(**{hash_field_name: value_hash})
    except queryset.model.DoesNotExist:
        pass

    instance = (
        queryset.filter(**{f"{hash_field_name}__isnull": True})
        .alias(plaintext_value=Cast(field_name, output_field=models.TextField()))
        .get(plaintext_value=value)
    )
    queryset.model._base_manager.filter(pk=instance.pk).update(
        **{hash_field_name: value_hash}
    )
    setattr(instance, hash_field_name, value_hash)
    return instance
