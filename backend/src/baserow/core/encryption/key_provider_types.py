import base64
import binascii
import hashlib
import os
import re
import secrets
import threading
from pathlib import Path
from typing import List, Optional, Tuple

from django.conf import settings

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .exceptions import DecryptionError, EncryptionConfigurationError
from .hashicorp_vault import HashiCorpVaultClient, get_vault_ciphertext_version
from .registries import KeyProviderType

KEY_LENGTH = 32
KEY_ID_LENGTH = 8
NONCE_LENGTH = 12


def generate_encryption_key() -> str:
    """Returns a new random key that can be added to BASEROW_ENCRYPTION_KEYS."""

    return base64.b64encode(secrets.token_bytes(KEY_LENGTH)).decode("ascii")


def decode_encryption_key(encoded_key: str) -> bytes:
    """
    Decodes a key configured in BASEROW_ENCRYPTION_KEYS. Both the standard and the
    URL safe base64 alphabets are accepted.

    :raises EncryptionConfigurationError: When the key isn't a base64 encoded 32
        byte value.
    """

    normalized = encoded_key.strip().replace("-", "+").replace("_", "/")
    try:
        key = base64.b64decode(normalized + "=" * (-len(normalized) % 4), validate=True)
    except (binascii.Error, ValueError):
        key = b""

    if len(key) != KEY_LENGTH:
        raise EncryptionConfigurationError(
            "Every key in BASEROW_ENCRYPTION_KEYS must be a base64 encoded 32 byte "
            "value. Generate one with `./baserow generate_encryption_key` or "
            "`openssl rand -base64 32`."
        )
    return key


def derive_key_from_secret_key() -> bytes:
    """
    Derives the local key encryption key that is used when no dedicated key is
    configured. SECRET_KEY is never stored in the database, so the encrypted values
    are still protected when only the database leaks.
    """

    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=b"baserow-encryption-at-rest",
        info=b"local-key-encryption-key",
    ).derive(settings.SECRET_KEY.encode("utf-8"))


def get_key_id(key: bytes) -> bytes:
    """
    Returns a short, non-secret identifier of a key encryption key. It's stored in
    front of every wrapped data key so that the right key can be selected to unwrap
    it after a rotation.
    """

    return hashlib.sha256(b"baserow-encryption-key-id:" + key).digest()[:KEY_ID_LENGTH]


def get_configured_encryption_keys() -> List[str]:
    """
    Returns the base64 encoded keys configured with BASEROW_ENCRYPTION_KEYS or with
    BASEROW_ENCRYPTION_KEYS_FILE, the primary key first.
    """

    keys = list(settings.BASEROW_ENCRYPTION_KEYS)
    keys_file = settings.BASEROW_ENCRYPTION_KEYS_FILE
    if not keys_file:
        return keys

    if keys:
        raise EncryptionConfigurationError(
            "Both BASEROW_ENCRYPTION_KEYS and BASEROW_ENCRYPTION_KEYS_FILE are set, "
            "but they are exclusive."
        )
    try:
        content = Path(keys_file).read_text()
    except OSError as exc:
        raise EncryptionConfigurationError(
            f"Could not read BASEROW_ENCRYPTION_KEYS_FILE {keys_file}: {exc.strerror}."
        ) from exc
    return [key for key in re.split(r"[\s,]+", content) if key]


class LocalKeyProviderType(KeyProviderType):
    """
    Wraps data keys with a key encryption key that is passed to Baserow with
    BASEROW_ENCRYPTION_KEYS or BASEROW_ENCRYPTION_KEYS_FILE. The first key wraps new
    data keys, the other keys can only unwrap, which makes it possible to rotate the
    key.

    Without any configured key, a key derived from SECRET_KEY is used, so values are
    always encrypted. That key is also always accepted to unwrap data keys, so
    configuring a dedicated key later doesn't break existing values. Run the
    `encrypt_data` management command to re-encrypt them with the new key.
    """

    type = "local"

    def __init__(self):
        super().__init__()
        self._keys: Optional[List[Tuple[bytes, bytes]]] = None
        self._lock = threading.Lock()

    def get_keys(self) -> List[Tuple[bytes, bytes]]:
        """
        Returns the `(key_id, key)` tuples of all the key encryption keys, the
        primary key first.
        """

        with self._lock:
            if self._keys is None:
                keys = [
                    decode_encryption_key(key)
                    for key in get_configured_encryption_keys()
                ]
                keys.append(derive_key_from_secret_key())

                self._keys = []
                for key in keys:
                    key_id = get_key_id(key)
                    if all(key_id != existing_id for existing_id, _ in self._keys):
                        self._keys.append((key_id, key))

            return self._keys

    def generate_data_key(self) -> Tuple[bytes, bytes]:
        key_id, key_encryption_key = self.get_keys()[0]
        data_key = AESGCM.generate_key(bit_length=KEY_LENGTH * 8)
        nonce = os.urandom(NONCE_LENGTH)
        wrapped_key = AESGCM(key_encryption_key).encrypt(nonce, data_key, key_id)
        return data_key, key_id + nonce + wrapped_key

    def unwrap_data_key(self, wrapped_key: bytes) -> bytes:
        key_id = wrapped_key[:KEY_ID_LENGTH]
        nonce = wrapped_key[KEY_ID_LENGTH : KEY_ID_LENGTH + NONCE_LENGTH]
        ciphertext = wrapped_key[KEY_ID_LENGTH + NONCE_LENGTH :]

        for candidate_id, key_encryption_key in self.get_keys():
            if candidate_id != key_id:
                continue
            try:
                return AESGCM(key_encryption_key).decrypt(nonce, ciphertext, key_id)
            except InvalidTag as exc:
                raise DecryptionError(
                    "The data key could not be unwrapped because it has been "
                    "tampered with."
                ) from exc

        raise DecryptionError(
            f"The value is protected by the local encryption key with id "
            f"{key_id.hex()}, which isn't configured. Add it to "
            f"BASEROW_ENCRYPTION_KEYS, or restore the SECRET_KEY that was used when "
            f"the value was encrypted."
        )

    def is_wrapped_with_current_key(
        self, wrapped_key: bytes, current_wrapped_key: bytes
    ) -> bool:
        return wrapped_key[:KEY_ID_LENGTH] == current_wrapped_key[:KEY_ID_LENGTH]

    def reset(self):
        with self._lock:
            self._keys = None


class HashiCorpVaultKeyProviderType(KeyProviderType):
    """
    Uses a key of the HashiCorp Vault Transit secrets engine as key encryption key.
    Vault generates the data keys and is the only one that can unwrap them, so the
    encrypted values can only be read by a Baserow instance that is allowed to use
    the Transit key. Unwrapped data keys are cached in memory, so Vault is only
    called when a process sees a data key for the first time.
    """

    type = "hashicorp_vault"

    def __init__(self):
        super().__init__()
        self._client: Optional[HashiCorpVaultClient] = None
        self._lock = threading.Lock()

    def get_client(self) -> HashiCorpVaultClient:
        with self._lock:
            if self._client is None:
                self._client = HashiCorpVaultClient.from_settings()
            return self._client

    def is_configured(self) -> bool:
        return bool(settings.BASEROW_VAULT_ADDR)

    def generate_data_key(self) -> Tuple[bytes, bytes]:
        data_key, wrapped_key = self.get_client().generate_data_key()
        return data_key, wrapped_key.encode("ascii")

    def unwrap_data_key(self, wrapped_key: bytes) -> bytes:
        return self.get_client().decrypt(wrapped_key.decode("ascii"))

    def is_wrapped_with_current_key(
        self, wrapped_key: bytes, current_wrapped_key: bytes
    ) -> bool:
        # A new data key is always wrapped with the latest version of the Transit
        # key, so every older version means that the Transit key was rotated.
        return get_vault_ciphertext_version(
            wrapped_key.decode("ascii")
        ) >= get_vault_ciphertext_version(current_wrapped_key.decode("ascii"))

    def reset(self):
        with self._lock:
            self._client = None
