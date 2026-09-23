import json

from django.core import checks, validators
from django.core.exceptions import FieldError
from django.db import models
from django.db.models.lookups import Exact, IsNull
from django.db.models.query_utils import DeferredAttribute

from .exceptions import EncryptionError
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


class EncryptedJSONMixin:
    """
    The plaintext of an `EncryptedJSONField` that remembers how it's stored in the
    database, see `EncryptedStr`. It can be changed in place, so it's only written
    back unchanged if it still serializes to the decrypted JSON.
    """

    def remember_stored_value(self, stored_value: str, plaintext: str):
        self.stored_value = stored_value
        self.plaintext = plaintext
        return self

    def is_unchanged(self, encoder) -> bool:
        return json.dumps(self, cls=encoder) == self.plaintext


class EncryptedDict(EncryptedJSONMixin, dict):
    def __reduce__(self):
        return dict, (dict(self),)


class EncryptedList(EncryptedJSONMixin, list):
    def __reduce__(self):
        return list, (list(self),)


class UndecryptedValue:
    """
    Loaded instead of an encrypted value that couldn't be decrypted, for example
    because HashiCorp Vault is unreachable or the key was removed, so that loading
    the row doesn't fail. Only reading the value from the model instance does, see
    `EncryptedAttribute`, and saving the row writes the stored value back unchanged.
    """

    __slots__ = ("stored_value",)

    def __init__(self, stored_value):
        self.stored_value = stored_value

    def __repr__(self):
        return "<UndecryptedValue>"

    def __reduce__(self):
        return UndecryptedValue, (self.stored_value,)


class EncryptedAttribute(DeferredAttribute):
    """
    Decrypts an `UndecryptedValue` when it's read, which raises the decryption error
    if it still can't be decrypted.
    """

    def __get__(self, instance, cls=None):
        value = super().__get__(instance, cls)
        if isinstance(value, UndecryptedValue):
            value = self.field.decrypt_stored_value(value.stored_value)
            instance.__dict__[self.field.attname] = value
        return value

    def __set__(self, instance, value):
        instance.__dict__[self.field.attname] = value


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

    def decrypt_stored_value(self, stored_value):
        """
        Returns the plaintext of an encrypted stored value.

        :raises EncryptionError: When the value can't be decrypted.
        """

        raise NotImplementedError

    def from_stored_value(self, stored_value):
        """
        Returns the plaintext of an encrypted stored value, or an `UndecryptedValue`
        if it can't be decrypted, so that the row can still be loaded.
        """

        try:
            return self.decrypt_stored_value(stored_value)
        except EncryptionError:
            return UndecryptedValue(stored_value)

    def pre_save(self, model_instance, add):
        # Reading the attribute would try to decrypt it, while it's written back
        # unchanged.
        value = model_instance.__dict__.get(self.attname)
        if isinstance(value, UndecryptedValue):
            return value
        return super().pre_save(model_instance, add)


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
    descriptor_class = EncryptedAttribute

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

    def decrypt_stored_value(self, stored_value):
        return EncryptedStr(EncryptionHandler().decrypt(stored_value), stored_value)

    def is_stored_unencrypted(self, raw_value) -> bool:
        return raw_value is None or raw_value == ""

    def get_prep_value(self, value):
        if isinstance(value, UndecryptedValue):
            return value.stored_value
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
        return self.from_stored_value(value)


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
    descriptor_class = EncryptedAttribute

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

    def decrypt_stored_value(self, stored_value):
        plaintext = EncryptionHandler().decrypt(stored_value)
        value = json.loads(plaintext, cls=self.decoder)
        if isinstance(value, dict):
            return EncryptedDict(value).remember_stored_value(stored_value, plaintext)
        if isinstance(value, list):
            return EncryptedList(value).remember_stored_value(stored_value, plaintext)
        return value

    def is_stored_unencrypted(self, raw_value) -> bool:
        return raw_value is None or raw_value == {} or raw_value == []

    def get_prep_value(self, value):
        if isinstance(value, UndecryptedValue):
            return value.stored_value
        if isinstance(value, EncryptedJSONMixin) and value.is_unchanged(self.encoder):
            return value.stored_value
        value = super().get_prep_value(value)
        if self.is_stored_unencrypted(value) or not is_encryption_enabled():
            return value
        return EncryptionHandler().encrypt(json.dumps(value, cls=self.encoder))

    def from_db_value(self, value, expression, connection):
        value = super().from_db_value(value, expression, connection)
        if EncryptionHandler.is_encrypted(value):
            return self.from_stored_value(value)
        return value
