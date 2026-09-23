import base64
import binascii
import hashlib
import hmac
import os
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, replace
from typing import Dict, List, NamedTuple, Optional, Tuple, Type

from django.apps import apps
from django.conf import settings
from django.core.signals import setting_changed
from django.db import DEFAULT_DB_ALIAS, models, transaction
from django.db.models.functions import Cast
from django.dispatch import receiver

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from loguru import logger

from baserow.core.exceptions import InstanceTypeDoesNotExist

from .exceptions import (
    DecryptionError,
    EncryptionConfigurationError,
    KeyProviderError,
)
from .registries import KeyProviderType, key_provider_type_registry

ENCRYPTED_VALUE_PREFIX = "bxenc:"
ENCRYPTED_VALUE_VERSION = "1"
# Only values that fully match the format are decrypted, other values, even if they
# happen to start with the prefix, were stored before encryption was enabled.
ENCRYPTED_VALUE_PATTERN = re.compile(
    r"^bxenc:1:([a-z][a-z0-9_]*):([A-Za-z0-9_-]+):([A-Za-z0-9_-]+)$"
)
NONCE_LENGTH = 12
TAG_LENGTH = 16
# A process starts using a new data key after this many seconds, so that a rotated
# key encryption key is picked up without a restart.
DATA_KEY_MAX_AGE_SECONDS = 24 * 60 * 60
# When the key provider can't generate a new data key, for example because Vault is
# unreachable, the current one keeps being used and a new one is tried after this
# many seconds.
DATA_KEY_RENEWAL_RETRY_SECONDS = 60
# The maximum number of unwrapped data keys a process keeps in memory.
DATA_KEY_CACHE_SIZE = 10_000


# How long a process trusts that encryption is still disabled before it reads the
# setting again. Once enabled, encryption is never disabled again.
ENCRYPTION_ENABLED_RECHECK_SECONDS = 10

_encryption_enabled = False
_encryption_enabled_checked_at: Optional[float] = None


def is_encryption_enabled() -> bool:
    """
    Indicates whether values are encrypted when they're written. After upgrading an
    existing instance, it's disabled until the `encrypt_data` management command
    enables it, so that the previous Baserow version, which keeps running during a
    rolling upgrade, can still read everything the new version writes. New instances
    have it enabled from the start.
    """

    global _encryption_enabled, _encryption_enabled_checked_at

    if _encryption_enabled:
        return True

    now = time.monotonic()
    if (
        _encryption_enabled_checked_at is None
        or now - _encryption_enabled_checked_at >= ENCRYPTION_ENABLED_RECHECK_SECONDS
    ):
        from baserow.core.models import Settings

        # Only this column is read, so that it also works in a data migration that
        # runs before a later migration adds a column to the settings. The primary
        # database is used because a read replica can lag behind.
        enabled = (
            Settings.objects.using(DEFAULT_DB_ALIAS)
            .values_list("encrypt_secrets_at_rest", flat=True)
            .first()
        )
        # Without settings yet, it's a new instance, which encrypts from the start.
        _encryption_enabled = enabled is None or enabled
        _encryption_enabled_checked_at = now
    return _encryption_enabled


def forget_encryption_enabled(enabled: bool = False):
    """
    Resets what this process knows about `is_encryption_enabled`. With `enabled`
    False, the setting is read again on the next call.
    """

    global _encryption_enabled, _encryption_enabled_checked_at

    _encryption_enabled = enabled
    _encryption_enabled_checked_at = None


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def get_encrypting_key_provider() -> KeyProviderType:
    """Returns the key provider selected with BASEROW_ENCRYPTION_PROVIDER."""

    provider_type = settings.BASEROW_ENCRYPTION_PROVIDER
    try:
        provider = key_provider_type_registry.get(provider_type)
    except InstanceTypeDoesNotExist as exc:
        raise EncryptionConfigurationError(
            f"BASEROW_ENCRYPTION_PROVIDER is set to the unknown provider "
            f"'{provider_type}', expected one of "
            f"{', '.join(key_provider_type_registry.get_types())}."
        ) from exc

    if not provider.is_configured():
        raise EncryptionConfigurationError(
            f"BASEROW_ENCRYPTION_PROVIDER is set to '{provider_type}', but that key "
            f"provider isn't configured."
        )
    return provider


def get_decrypting_key_provider(provider_type: str) -> KeyProviderType:
    """Returns the key provider that wrapped the data key of an encrypted value."""

    try:
        provider = key_provider_type_registry.get(provider_type)
    except InstanceTypeDoesNotExist as exc:
        raise DecryptionError(
            f"The value is encrypted with the unknown key provider '{provider_type}'."
        ) from exc

    if not provider.is_configured():
        raise DecryptionError(
            f"The value is encrypted with the '{provider_type}' key provider, which "
            f"isn't configured."
        )
    return provider


@dataclass(frozen=True)
class DataKey:
    provider_type: str
    wrapped_key: str
    key: bytes
    expires_at: float


@dataclass
class EncryptedFieldReport:
    field: str
    values: int = 0
    to_encrypt: int = 0
    encrypted: int = 0
    failed: int = 0


class EncryptedValue(NamedTuple):
    provider_type: str
    wrapped_key: str
    nonce: bytes
    ciphertext: bytes
    header: str


class Keyring:
    """
    Keeps the data keys of the current process in memory. A single data key is used
    to encrypt new values until it expires. Data keys found in existing values are
    unwrapped by their key provider once and then cached, so a remote key provider
    like HashiCorp Vault isn't called for every value.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._current: Optional[DataKey] = None
        self._unwrapped: Dict[Tuple[str, str], bytes] = OrderedDict()

    def get_current_data_key(self) -> DataKey:
        with self._lock:
            now = time.monotonic()
            if self._current is None or self._current.expires_at <= now:
                provider = get_encrypting_key_provider()
                try:
                    key, wrapped_key = provider.generate_data_key()
                except KeyProviderError:
                    if self._current is None or (
                        self._current.provider_type != provider.type
                    ):
                        raise
                    logger.exception(
                        "Could not generate a new data key, the current one is used "
                        "until the key provider is reachable again."
                    )
                    self._current = replace(
                        self._current,
                        expires_at=now + DATA_KEY_RENEWAL_RETRY_SECONDS,
                    )
                    return self._current
                self._current = DataKey(
                    provider_type=provider.type,
                    wrapped_key=_b64encode(wrapped_key),
                    key=key,
                    expires_at=now + DATA_KEY_MAX_AGE_SECONDS,
                )
                self._remember(provider.type, self._current.wrapped_key, key)
            return self._current

    def get_data_key(self, provider_type: str, wrapped_key: str) -> bytes:
        cache_key = (provider_type, wrapped_key)
        with self._lock:
            key = self._unwrapped.get(cache_key)
            if key is not None:
                self._unwrapped.move_to_end(cache_key)
                return key

        provider = get_decrypting_key_provider(provider_type)
        try:
            wrapped_key_bytes = _b64decode(wrapped_key)
        except (binascii.Error, ValueError) as exc:
            raise DecryptionError("The wrapped data key is malformed.") from exc

        # Unwrapping can be a network call, so it's done without holding the lock.
        key = provider.unwrap_data_key(wrapped_key_bytes)
        with self._lock:
            self._remember(provider_type, wrapped_key, key)
        return key

    def _remember(self, provider_type: str, wrapped_key: str, key: bytes):
        self._unwrapped[(provider_type, wrapped_key)] = key
        self._unwrapped.move_to_end((provider_type, wrapped_key))
        while len(self._unwrapped) > DATA_KEY_CACHE_SIZE:
            self._unwrapped.popitem(last=False)

    def reset(self):
        with self._lock:
            self._current = None
            self._unwrapped.clear()
        for provider in key_provider_type_registry.get_all():
            provider.reset()


keyring = Keyring()


@receiver(setting_changed)
def reset_keyring_on_setting_change(setting, **kwargs):
    if setting == "SECRET_KEY" or setting.startswith(
        ("BASEROW_ENCRYPTION_", "BASEROW_VAULT_")
    ):
        keyring.reset()


class EncryptionHandler:
    """
    Encrypts values at rest with envelope encryption. Every value is encrypted with
    AES-256-GCM using a data key. The data key is wrapped by a key encryption key
    that is held by a key provider (a local key or HashiCorp Vault) and never stored
    in the database. An encrypted value is self-contained:

        bxenc:1:<key provider>:<wrapped data key>:<nonce + ciphertext + tag>

    The header before the ciphertext is authenticated as additional data, so the
    value can't be combined with another data key without detection.
    """

    @classmethod
    def is_encrypted(cls, value) -> bool:
        return cls._parse(value) is not None

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts the provided plaintext with the current data key.

        :param plaintext: The value to encrypt.
        :raises EncryptionConfigurationError: When the key provider isn't configured.
        :raises KeyProviderError: When the key provider can't be reached.
        :return: The self-contained encrypted value.
        """

        data_key = keyring.get_current_data_key()
        header = (
            f"{ENCRYPTED_VALUE_PREFIX}{ENCRYPTED_VALUE_VERSION}:"
            f"{data_key.provider_type}:{data_key.wrapped_key}"
        )
        nonce = os.urandom(NONCE_LENGTH)
        ciphertext = AESGCM(data_key.key).encrypt(
            nonce, plaintext.encode("utf-8"), header.encode("ascii")
        )
        return f"{header}:{_b64encode(nonce + ciphertext)}"

    def decrypt(self, value: str) -> str:
        """
        Decrypts a value returned by `encrypt`. Values that aren't encrypted, for
        example because they were stored before the column was encrypted, are
        returned as they are.

        :param value: The encrypted value.
        :raises DecryptionError: When the value can't be decrypted.
        :return: The plaintext.
        """

        encrypted = self._parse(value)
        if encrypted is None:
            return value

        key = keyring.get_data_key(encrypted.provider_type, encrypted.wrapped_key)
        try:
            plaintext = AESGCM(key).decrypt(
                encrypted.nonce, encrypted.ciphertext, encrypted.header.encode("ascii")
            )
        except InvalidTag as exc:
            raise DecryptionError(
                "The value could not be decrypted because it has been tampered with."
            ) from exc
        return plaintext.decode("utf-8")

    def needs_reencryption(self, value: str) -> bool:
        """
        Indicates whether a stored value must be (re-)encrypted: because it's still
        in plain text, or because its data key isn't protected by the current key
        encryption key anymore, after a key rotation or a key provider change.

        :param value: The raw value as stored in the database.
        """

        if value is None or value == "":
            return False
        encrypted = self._parse(value)
        if encrypted is None:
            return True

        current = keyring.get_current_data_key()
        if encrypted.provider_type != current.provider_type:
            return True
        if encrypted.wrapped_key == current.wrapped_key:
            return False

        provider = get_decrypting_key_provider(encrypted.provider_type)
        return not provider.is_wrapped_with_current_key(
            _b64decode(encrypted.wrapped_key), _b64decode(current.wrapped_key)
        )

    def check_key_provider(self):
        """
        Makes sure that the configured key provider can generate a data key and unwrap
        it again, e.g. that HashiCorp Vault is reachable and Baserow has access to the
        Transit key.

        :raises EncryptionError: When the key provider can't be used.
        """

        provider = get_encrypting_key_provider()
        key, wrapped_key = provider.generate_data_key()
        if not hmac.compare_digest(provider.unwrap_data_key(wrapped_key), key):
            raise KeyProviderError(
                f"The '{provider.type}' key provider unwrapped a data key incorrectly."
            )

    def enable_encryption(self) -> bool:
        """
        Makes every Baserow process encrypt the values it writes, see
        `is_encryption_enabled`.

        :return: Whether encryption was disabled before.
        """

        from baserow.core.cache import invalidate_cached_settings
        from baserow.core.models import Settings

        enabled = (
            Settings.objects.filter(encrypt_secrets_at_rest=False).update(
                encrypt_secrets_at_rest=True
            )
            > 0
        )
        invalidate_cached_settings()
        transaction.on_commit(invalidate_cached_settings)
        forget_encryption_enabled(enabled=True)
        return enabled

    def encrypt_existing_values(
        self, dry_run: bool = False, batch_size: int = 100
    ) -> List[EncryptedFieldReport]:
        """
        Encrypts all the values of encrypted fields that are still stored in plain
        text, and re-encrypts the values whose data key isn't protected by the
        current key encryption key anymore. Enables encryption of new values first,
        once the key provider works. Must be run once every instance runs a version
        with encryption at rest, and after every rotation of the key encryption key.

        A value is only rewritten if it hasn't changed since it was read, so it's safe
        to run while Baserow is running. No rows are locked.

        :param dry_run: Only count the values that must be (re-)encrypted.
        :param batch_size: The number of rows that are read at once.
        :raises EncryptionError: When the key provider can't be used.
        :return: A report per encrypted field.
        """

        from .fields import EncryptedFieldMixin

        # Enabling encryption with a key provider that doesn't work would make every
        # write of a secret fail.
        self.check_key_provider()
        if not dry_run:
            self.enable_encryption()

        reports = []
        for model in apps.get_models():
            if model._meta.proxy or not model._meta.managed:
                continue
            fields = [
                field
                for field in model._meta.local_concrete_fields
                if isinstance(field, EncryptedFieldMixin)
            ]
            if fields:
                reports.extend(
                    self._encrypt_existing_model_values(
                        model, fields, dry_run, batch_size
                    )
                )
        return reports

    def _encrypt_existing_model_values(
        self,
        model: Type[models.Model],
        fields: List[models.Field],
        dry_run: bool,
        batch_size: int,
    ) -> List[EncryptedFieldReport]:
        reports = {
            field.name: EncryptedFieldReport(f"{model._meta.label}.{field.name}")
            for field in fields
        }
        # Casting to a regular field returns the stored values without decrypting.
        raw_values = {
            f"encryption_raw_{field.name}": Cast(
                field.name, output_field=field.get_raw_output_field()
            )
            for field in fields
        }
        queryset = model._base_manager.annotate(**raw_values).order_by("pk")

        last_pk = None
        while True:
            batch = queryset if last_pk is None else queryset.filter(pk__gt=last_pk)
            rows = list(batch.values_list("pk", *raw_values.keys())[:batch_size])
            if not rows:
                break
            last_pk = rows[-1][0]

            for pk, *values in rows:
                stale_values = {}
                for field, value in zip(fields, values):
                    if field.is_stored_unencrypted(value):
                        continue
                    report = reports[field.name]
                    report.values += 1
                    try:
                        if not field.raw_value_needs_reencryption(value):
                            continue
                        plaintext = field.raw_value_to_python(value)
                    except DecryptionError:
                        report.failed += 1
                        continue
                    report.to_encrypt += 1
                    stale_values[field] = (value, plaintext)

                if stale_values and not dry_run:
                    if self._rewrite_values(model, pk, stale_values):
                        for field in stale_values:
                            reports[field.name].encrypted += 1

        return list(reports.values())

    def _rewrite_values(
        self,
        model: Type[models.Model],
        pk,
        stale_values: Dict[models.Field, Tuple[object, object]],
    ) -> bool:
        """
        Writes the plaintext of the stale values again, so that they're encrypted with
        the current data key, but only if the stored values didn't change since they
        were read. A value changed in the meantime is written by the application, and
        thus already encrypted.

        :return: Whether the row was updated.
        """

        from .mixins import LookupHashMixin

        queryset = model._base_manager.filter(pk=pk)
        updates = {}
        for field, (stored_value, plaintext) in stale_values.items():
            alias = f"encryption_stored_{field.name}"
            queryset = queryset.alias(
                **{alias: Cast(field.name, output_field=field.get_raw_output_field())}
            ).filter(**{alias: stored_value})
            updates[field.name] = plaintext

        if issubclass(model, LookupHashMixin):
            for field_name, hash_field_name in model.lookup_hash_fields.items():
                if field_name in updates:
                    plaintext = updates[field_name]
                    updates[hash_field_name] = (
                        self.hash_for_lookup(plaintext) if plaintext else None
                    )

        return queryset.update(**updates) > 0

    @staticmethod
    def hash_for_lookup(value: str) -> str:
        """
        Returns a hash that can be stored next to an encrypted value to find the row
        by value, like an API token. Only use this for random, high entropy values
        because the hash isn't salted.
        """

        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _parse(value) -> Optional[EncryptedValue]:
        """
        Parses an encrypted value, or returns None when the value doesn't match the
        format of an encrypted value and thus is a value stored in plain text.
        """

        if not isinstance(value, str) or not value.startswith(ENCRYPTED_VALUE_PREFIX):
            return None
        match = ENCRYPTED_VALUE_PATTERN.match(value)
        if match is None:
            return None

        provider_type, wrapped_key, payload = match.groups()
        try:
            _b64decode(wrapped_key)
            payload_bytes = _b64decode(payload)
        except (binascii.Error, ValueError):
            return None
        if len(payload_bytes) < NONCE_LENGTH + TAG_LENGTH:
            return None

        return EncryptedValue(
            provider_type=provider_type,
            wrapped_key=wrapped_key,
            nonce=payload_bytes[:NONCE_LENGTH],
            ciphertext=payload_bytes[NONCE_LENGTH:],
            header=value[: value.rindex(":")],
        )
