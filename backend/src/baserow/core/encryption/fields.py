import json

from django.core import checks, validators
from django.core.exceptions import FieldError
from django.db import models
from django.db.models.lookups import Exact, IsNull

from .handler import EncryptionHandler, is_encryption_enabled


class EncryptedStr(str):
    """
    The plaintext of an `EncryptedTextField` that remembers how it's stored in the
    database. Saving it unchanged writes back the stored ciphertext, so saving a row
    doesn't re-encrypt its secrets. It's pickled and copied as a regular string.
    """

    def __new__(cls, value: str, stored_value: str):
        instance = super().__new__(cls, value)
        instance.stored_value = stored_value
        return instance

    def __reduce__(self):
        return str, (str(self),)


class EncryptedEmptyExact(Exact):
    """
    Encrypted values can't be compared by the database because every value is
    encrypted with a random nonce. Only comparing with an empty string is supported,
    because empty strings are stored as they are.
    """

    def get_prep_lookup(self):
        if self.rhs not in ("", None) and not hasattr(self.rhs, "resolve_expression"):
            raise FieldError(
                f"The field {getattr(self.lhs, 'target', '')} is encrypted and can't "
                f"be filtered by value. Store `EncryptionHandler.hash_for_lookup` of "
                f"the value in a separate column if it must be looked up."
            )
        return super().get_prep_lookup()


class EncryptedFieldMixin:
    """
    Shared by the encrypted fields. Used by `EncryptionHandler.
    encrypt_existing_values` to find the stored values that must be (re-)encrypted.
    """

    def get_raw_output_field(self) -> models.Field:
        """
        Returns the field to cast the column to, to read the stored values without
        decrypting them.
        """

        raise NotImplementedError

    def is_stored_unencrypted(self, raw_value) -> bool:
        """Indicates whether a stored value is left unencrypted on purpose."""

        raise NotImplementedError

    def raw_value_needs_reencryption(self, raw_value) -> bool:
        if not isinstance(raw_value, str):
            return True
        return EncryptionHandler().needs_reencryption(raw_value)

    def raw_value_to_python(self, raw_value):
        """Returns the plaintext of a value read with `get_raw_output_field`."""

        raise NotImplementedError


class EncryptedTextField(EncryptedFieldMixin, models.TextField):
    """
    A text field that is transparently encrypted at rest with the configured key
    provider, see `EncryptionHandler`. The model instance always holds the
    plaintext, only the database stores the ciphertext.

    - Empty strings and None are stored as they are.
    - A value that was stored before the column became encrypted is returned as it
      is, so converting an existing column doesn't need a data migration. The
      `encrypt_data` management command encrypts those values afterwards.
    - Values are written in plain text until encryption is enabled, see
      `is_encryption_enabled`.
    - The database can't compare encrypted values, so filtering and uniqueness
      aren't supported. Only `isnull` and comparing with an empty string are.
    """

    description = "Text encrypted at rest"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # The column is a text column because the ciphertext is longer than the
        # plaintext, but the plaintext still respects the `max_length`.
        if self.max_length is not None:
            self.validators.append(validators.MaxLengthValidator(self.max_length))

    def check(self, **kwargs):
        errors = super().check(**kwargs)
        if self._unique or self.db_index:
            errors.append(
                checks.Error(
                    "Encrypted fields can't be unique or indexed because every value "
                    "is encrypted with a random nonce.",
                    hint="Index a separate column containing "
                    "`EncryptionHandler.hash_for_lookup(value)` instead.",
                    obj=self,
                    id="baserow.encryption.E001",
                )
            )
        return errors

    def get_lookup(self, lookup_name):
        if lookup_name == "exact":
            return EncryptedEmptyExact
        if lookup_name == "isnull":
            return IsNull
        return None

    def get_transform(self, lookup_name):
        return None

    def get_raw_output_field(self) -> models.Field:
        return models.TextField()

    def raw_value_to_python(self, raw_value):
        return EncryptionHandler().decrypt(raw_value)

    def is_stored_unencrypted(self, raw_value) -> bool:
        return raw_value is None or raw_value == ""

    def get_prep_value(self, value):
        if isinstance(value, EncryptedStr) and EncryptionHandler.is_encrypted(
            value.stored_value
        ):
            return value.stored_value
        value = super().get_prep_value(value)
        if self.is_stored_unencrypted(value):
            return value
        if not is_encryption_enabled():
            return str(value)
        return EncryptionHandler().encrypt(value)

    def from_db_value(self, value, expression, connection):
        if self.is_stored_unencrypted(value):
            return value
        return EncryptedStr(EncryptionHandler().decrypt(value), value)


class EncryptedJSONField(EncryptedFieldMixin, models.JSONField):
    """
    A JSON field whose whole value is transparently encrypted at rest, see
    `EncryptedTextField`. The database stores the encrypted value as a JSON string.

    - None and empty dicts and lists are stored as they are.
    - A value that was stored before the column became encrypted is returned as it
      is. The `encrypt_data` management command encrypts those values afterwards.
    - The database can't read the encrypted JSON, so key, containment and
      comparison lookups aren't supported. Only `isnull` is.
    """

    description = "JSON encrypted at rest"

    def get_lookup(self, lookup_name):
        if lookup_name == "isnull":
            return IsNull
        return None

    def get_transform(self, lookup_name):
        return None

    def get_raw_output_field(self) -> models.Field:
        return models.JSONField()

    def raw_value_to_python(self, raw_value):
        if EncryptionHandler.is_encrypted(raw_value):
            return json.loads(EncryptionHandler().decrypt(raw_value), cls=self.decoder)
        return raw_value

    def is_stored_unencrypted(self, raw_value) -> bool:
        return raw_value is None or raw_value == {} or raw_value == []

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if self.is_stored_unencrypted(value) or not is_encryption_enabled():
            return value
        return EncryptionHandler().encrypt(json.dumps(value, cls=self.encoder))

    def from_db_value(self, value, expression, connection):
        value = super().from_db_value(value, expression, connection)
        if EncryptionHandler.is_encrypted(value):
            return json.loads(EncryptionHandler().decrypt(value), cls=self.decoder)
        return value
