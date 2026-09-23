import base64
import hashlib
from unittest.mock import patch

from django.test import override_settings

import pytest

from baserow.core.encryption.exceptions import (
    DecryptionError,
    EncryptionConfigurationError,
)
from baserow.core.encryption.handler import (
    ENCRYPTED_VALUE_PREFIX,
    EncryptionHandler,
    keyring,
)
from baserow.core.encryption.key_provider_types import (
    decode_encryption_key,
    generate_encryption_key,
)


def test_encrypt_and_decrypt_round_trip():
    handler = EncryptionHandler()

    for plaintext in ["xoxb-slack-token", "ünïcödé 🔐", "a" * 10_000]:
        encrypted = handler.encrypt(plaintext)

        assert encrypted.startswith(ENCRYPTED_VALUE_PREFIX)
        assert plaintext not in encrypted
        assert handler.is_encrypted(encrypted)
        assert handler.decrypt(encrypted) == plaintext


def test_encrypting_the_same_value_twice_gives_different_ciphertexts():
    handler = EncryptionHandler()

    first = handler.encrypt("secret")
    second = handler.encrypt("secret")

    assert first != second
    assert handler.decrypt(first) == handler.decrypt(second) == "secret"


def test_decrypt_returns_values_that_are_not_encrypted_as_they_are():
    handler = EncryptionHandler()

    assert handler.decrypt("stored before the column was encrypted") == (
        "stored before the column was encrypted"
    )
    assert handler.needs_reencryption("stored before the column was encrypted")
    assert not handler.needs_reencryption("")
    assert not handler.needs_reencryption(None)


def test_decrypt_detects_tampering():
    handler = EncryptionHandler()
    encrypted = handler.encrypt("secret")
    header, payload = encrypted.rsplit(":", 1)
    raw = bytearray(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    raw[-1] ^= 1
    tampered = f"{header}:{base64.urlsafe_b64encode(bytes(raw)).decode()}"

    with pytest.raises(DecryptionError):
        handler.decrypt(tampered)


@pytest.mark.parametrize(
    "value",
    [
        "bxenc:1:local:not-enough-parts",
        "bxenc:2:local:abc:def",
        "bxenc:1:unknown_provider:abc:def",
        "bxenc:1:local:!!!:def",
        "bxenc:1:lócal:abc:def",
    ],
)
def test_decrypt_rejects_malformed_values(value):
    with pytest.raises(DecryptionError):
        EncryptionHandler().decrypt(value)


def test_values_encrypted_without_dedicated_key_stay_readable_with_one():
    handler = EncryptionHandler()
    encrypted_with_secret_key = handler.encrypt("secret")

    with override_settings(BASEROW_ENCRYPTION_KEYS=[generate_encryption_key()]):
        assert handler.decrypt(encrypted_with_secret_key) == "secret"
        assert handler.needs_reencryption(encrypted_with_secret_key)
        assert not handler.needs_reencryption(handler.encrypt("new"))


def test_rotating_the_local_key():
    handler = EncryptionHandler()
    old_key, new_key = generate_encryption_key(), generate_encryption_key()

    with override_settings(BASEROW_ENCRYPTION_KEYS=[old_key]):
        encrypted = handler.encrypt("secret")
        assert not handler.needs_reencryption(encrypted)

    with override_settings(BASEROW_ENCRYPTION_KEYS=[new_key, old_key]):
        assert handler.decrypt(encrypted) == "secret"
        assert handler.needs_reencryption(encrypted)
        reencrypted = handler.encrypt(handler.decrypt(encrypted))

    with override_settings(BASEROW_ENCRYPTION_KEYS=[new_key]):
        assert handler.decrypt(reencrypted) == "secret"
        with pytest.raises(DecryptionError, match="isn't configured"):
            handler.decrypt(encrypted)


def test_changing_the_secret_key_without_dedicated_key_breaks_decryption():
    handler = EncryptionHandler()
    encrypted = handler.encrypt("secret")

    with override_settings(SECRET_KEY="another-secret-key"):
        with pytest.raises(DecryptionError):
            handler.decrypt(encrypted)


@pytest.mark.parametrize("key", ["too-short", base64.b64encode(b"x" * 16).decode()])
def test_invalid_local_keys_are_rejected(key):
    with override_settings(BASEROW_ENCRYPTION_KEYS=[key]):
        with pytest.raises(EncryptionConfigurationError):
            EncryptionHandler().encrypt("secret")


def test_generated_keys_can_be_decoded_in_both_base64_alphabets():
    key = generate_encryption_key()
    url_safe_key = key.replace("+", "-").replace("/", "_").rstrip("=")

    assert len(decode_encryption_key(key)) == 32
    assert decode_encryption_key(url_safe_key) == decode_encryption_key(key)


def test_keys_can_be_read_from_a_file(tmp_path):
    handler = EncryptionHandler()
    old_key, new_key = generate_encryption_key(), generate_encryption_key()
    keys_file = tmp_path / "keys"
    keys_file.write_text(f"{new_key}\n{old_key}\n")

    with override_settings(BASEROW_ENCRYPTION_KEYS=[old_key]):
        encrypted = handler.encrypt("secret")

    with override_settings(BASEROW_ENCRYPTION_KEYS_FILE=str(keys_file)):
        assert handler.decrypt(encrypted) == "secret"
        assert handler.needs_reencryption(encrypted)

    with override_settings(
        BASEROW_ENCRYPTION_KEYS=[old_key], BASEROW_ENCRYPTION_KEYS_FILE=str(keys_file)
    ):
        with pytest.raises(EncryptionConfigurationError, match="exclusive"):
            handler.encrypt("secret")


def test_unknown_or_unconfigured_encryption_provider_is_rejected():
    with override_settings(BASEROW_ENCRYPTION_PROVIDER="unknown"):
        with pytest.raises(EncryptionConfigurationError):
            EncryptionHandler().encrypt("secret")

    with override_settings(
        BASEROW_ENCRYPTION_PROVIDER="hashicorp_vault", BASEROW_VAULT_ADDR=""
    ):
        with pytest.raises(EncryptionConfigurationError):
            EncryptionHandler().encrypt("secret")


def test_data_key_is_reused_until_it_expires():
    handler = EncryptionHandler()

    def data_key_of(encrypted):
        return encrypted.split(":")[3]

    first = handler.encrypt("a")
    assert data_key_of(handler.encrypt("b")) == data_key_of(first)

    with patch("baserow.core.encryption.handler.DATA_KEY_MAX_AGE_SECONDS", -1):
        keyring.reset()
        expiring = handler.encrypt("c")
        assert data_key_of(handler.encrypt("d")) != data_key_of(expiring)

    # Values encrypted with an expired data key of the same key encryption key
    # don't need to be re-encrypted.
    assert handler.decrypt(first) == "a"
    assert not handler.needs_reencryption(first)


def test_hash_for_lookup_is_the_sha256_of_the_value():
    assert EncryptionHandler.hash_for_lookup("abc") == (
        hashlib.sha256(b"abc").hexdigest()
    )
