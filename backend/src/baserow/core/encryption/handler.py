import base64
import binascii
import hashlib
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, List, NamedTuple, Optional, Tuple, Type

from django.apps import apps
from django.conf import settings
from django.core.signals import setting_changed
from django.db import models, transaction
from django.db.models.functions import Cast
from django.dispatch import receiver

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from baserow.core.exceptions import InstanceTypeDoesNotExist

from .exceptions import DecryptionError, EncryptionConfigurationError
from .registries import KeyProviderType, key_provider_type_registry

ENCRYPTED_VALUE_PREFIX = "bxenc:"
ENCRYPTED_VALUE_VERSION = "1"
NONCE_LENGTH = 12
# A process starts using a new data key after this many seconds, so that a rotated
# key encryption key is picked up without a restart.
DATA_KEY_MAX_AGE_SECONDS = 60 * 60
# The maximum number of unwrapped data keys a process keeps in memory.
DATA_KEY_CACHE_SIZE = 1024


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
                key, wrapped_key = provider.generate_data_key()
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

    @staticmethod
    def is_encrypted(value) -> bool:
        return isinstance(value, str) and value.startswith(ENCRYPTED_VALUE_PREFIX)

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

        if not self.is_encrypted(value):
            return value

        encrypted = self._parse(value)
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
        if not self.is_encrypted(value):
            return True

        encrypted = self._parse(value)
        current = keyring.get_current_data_key()
        if encrypted.provider_type != current.provider_type:
            return True
        if encrypted.wrapped_key == current.wrapped_key:
            return False

        provider = get_decrypting_key_provider(encrypted.provider_type)
        return not provider.is_wrapped_with_current_key(
            _b64decode(encrypted.wrapped_key), _b64decode(current.wrapped_key)
        )

    def encrypt_existing_values(
        self, dry_run: bool = False, batch_size: int = 500
    ) -> List[EncryptedFieldReport]:
        """
        Encrypts all the values of encrypted fields that are still stored in plain
        text, and re-encrypts the values whose data key isn't protected by the
        current key encryption key anymore. Must be run after upgrading and after
        every rotation of the key encryption key.

        :param dry_run: Only count the values that must be (re-)encrypted.
        :param batch_size: The number of rows that are processed at once.
        :return: A report per encrypted field.
        """

        from .fields import EncryptedFieldMixin

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

            stale_fields_per_pk = {}
            for pk, *values in rows:
                for field, value in zip(fields, values):
                    if field.is_stored_unencrypted(value):
                        continue
                    report = reports[field.name]
                    report.values += 1
                    try:
                        needs_reencryption = field.raw_value_needs_reencryption(value)
                    except DecryptionError:
                        report.failed += 1
                        continue
                    if needs_reencryption:
                        report.to_encrypt += 1
                        stale_fields_per_pk.setdefault(pk, []).append(field.name)

            if stale_fields_per_pk and not dry_run:
                self._save_encrypted_fields(model, stale_fields_per_pk, reports)

        return list(reports.values())

    def _save_encrypted_fields(
        self,
        model: Type[models.Model],
        stale_fields_per_pk: Dict[int, List[str]],
        reports: Dict[str, EncryptedFieldReport],
    ):
        """
        Writes the stale fields again, so that they're encrypted with the current
        data key. If a value of the batch can't be decrypted, the rows are written
        one by one so that all the other values are still encrypted.
        """

        field_names = {name for names in stale_fields_per_pk.values() for name in names}
        try:
            with transaction.atomic():
                self._rewrite_encrypted_fields(
                    model, list(stale_fields_per_pk.keys()), field_names
                )
            return
        except DecryptionError:
            pass

        for pk, names in stale_fields_per_pk.items():
            try:
                with transaction.atomic():
                    self._rewrite_encrypted_fields(model, [pk], set(names))
            except DecryptionError:
                for name in names:
                    reports[name].to_encrypt -= 1
                    reports[name].failed += 1

    def _rewrite_encrypted_fields(
        self, model: Type[models.Model], pks: List[int], field_names: set
    ):
        from .mixins import LookupHashMixin

        # Loading the instances decrypts the values, writing them encrypts them
        # again with the current data key. The rows are locked so that a concurrent
        # change can't be overwritten with the value loaded here.
        instances = list(
            model._base_manager.select_for_update()
            .filter(pk__in=pks)
            .only("pk", *field_names)
        )
        if issubclass(model, LookupHashMixin):
            for instance in instances:
                instance.refresh_lookup_hashes()
            field_names = field_names | {
                hash_field_name
                for field_name, hash_field_name in model.lookup_hash_fields.items()
                if field_name in field_names
            }
        model._base_manager.bulk_update(instances, list(field_names))

    @staticmethod
    def hash_for_lookup(value: str) -> str:
        """
        Returns a hash that can be stored next to an encrypted value to find the row
        by value, like an API token. Only use this for random, high entropy values
        because the hash isn't salted.
        """

        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _parse(value: str) -> EncryptedValue:
        parts = value.split(":")
        if (
            not value.isascii()
            or len(parts) != 5
            or parts[1] != ENCRYPTED_VALUE_VERSION
        ):
            raise DecryptionError("The encrypted value has an unsupported format.")

        _, _, provider_type, wrapped_key, payload = parts
        try:
            payload_bytes = _b64decode(payload)
        except (binascii.Error, ValueError) as exc:
            raise DecryptionError("The encrypted value is malformed.") from exc

        return EncryptedValue(
            provider_type=provider_type,
            wrapped_key=wrapped_key,
            nonce=payload_bytes[:NONCE_LENGTH],
            ciphertext=payload_bytes[NONCE_LENGTH:],
            header=value[: value.rindex(":")],
        )
