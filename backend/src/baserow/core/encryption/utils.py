import hmac

from django.db import models
from django.db.models.functions import Cast

from .fields import EncryptedFieldMixin, EncryptedStr
from .handler import EncryptionHandler, is_encryption_enabled

STORED_VALUE_ANNOTATION = "lookup_hash_stored_value"


def defer_encrypted_fields(queryset: models.QuerySet) -> models.QuerySet:
    """
    Defers the encrypted fields of the queryset's model, so that they aren't loaded
    and decrypted when they aren't needed, for example in public responses.
    """

    names = [
        field.name
        for field in queryset.model._meta.concrete_fields
        if isinstance(field, EncryptedFieldMixin)
    ]
    # `defer()` without arguments would clear the fields deferred before.
    return queryset.defer(*names) if names else queryset


def get_by_lookup_hash(
    queryset: models.QuerySet,
    value: str,
    field_name: str = "key",
    hash_field_name: str = "key_hash",
) -> models.Model:
    """
    Returns the object whose encrypted `field_name` equals `value`, by comparing the
    lookup hash stored in `hash_field_name`. The encrypted field is never decrypted,
    so the key provider isn't needed to find the object, e.g. to authenticate a
    request with an API token while HashiCorp Vault is unreachable.

    Until encryption is enabled, the previous Baserow version can still be running
    and it writes keys in plain text without updating the hash. Those rows are found
    by their plain text key, and their hash is updated.

    :param queryset: The queryset to find the object in.
    :param value: The plain text value to look for, e.g. an API token.
    :param field_name: The name of the encrypted field.
    :param hash_field_name: The name of the field containing the lookup hash.
    :raises queryset.model.DoesNotExist: When no object matches the value.
    :return: The matching object.
    """

    model = queryset.model
    value_hash = EncryptionHandler.hash_for_lookup(value)
    # The value is read as it's stored, without decrypting it.
    queryset = queryset.defer(field_name).annotate(
        **{STORED_VALUE_ANNOTATION: Cast(field_name, output_field=models.TextField())}
    )

    try:
        instance = queryset.get(**{hash_field_name: value_hash})
    except model.DoesNotExist:
        instance = None

    if instance is not None:
        stored_value = vars(instance).pop(STORED_VALUE_ANNOTATION)
        # Only this version encrypts, and it writes the hash in the same query as the
        # encrypted value, so the hash of an encrypted value is always up to date. The
        # previous version writes keys in plain text without updating the hash, so a
        # hash can belong to an older key that isn't valid anymore.
        if EncryptionHandler.is_encrypted(stored_value) or hmac.compare_digest(
            stored_value.encode(), value.encode()
        ):
            setattr(instance, field_name, EncryptedStr(value, stored_value))
            return instance
        _store_lookup_hash(model, instance, hash_field_name, stored_value)
        raise model.DoesNotExist()

    # Once encryption is enabled every key has a hash, and a value that looks
    # encrypted must never match a stored ciphertext.
    if is_encryption_enabled() or EncryptionHandler.is_encrypted(value):
        raise model.DoesNotExist()

    instance = queryset.filter(**{STORED_VALUE_ANNOTATION: value}).first()
    if instance is None:
        raise model.DoesNotExist()

    stored_value = vars(instance).pop(STORED_VALUE_ANNOTATION)
    setattr(instance, field_name, EncryptedStr(value, stored_value))
    _store_lookup_hash(model, instance, hash_field_name, value)
    return instance


def _store_lookup_hash(model, instance, hash_field_name: str, value: str):
    value_hash = EncryptionHandler.hash_for_lookup(value)
    model._base_manager.filter(pk=instance.pk).update(**{hash_field_name: value_hash})
    setattr(instance, hash_field_name, value_hash)
