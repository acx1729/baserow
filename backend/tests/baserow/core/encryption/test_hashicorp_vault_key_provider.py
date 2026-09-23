import base64
import json
import os

from django.test import override_settings

import pytest
import requests
import responses

from baserow.core.encryption.exceptions import (
    DecryptionError,
    EncryptionConfigurationError,
    KeyProviderError,
)
from baserow.core.encryption.handler import EncryptionHandler, keyring

VAULT_ADDR = "https://vault.example.com:8200"
DATAKEY_URL = f"{VAULT_ADDR}/v1/transit/datakey/plaintext/baserow"
DECRYPT_URL = f"{VAULT_ADDR}/v1/transit/decrypt/baserow"


class FakeTransitKey:
    """
    Imitates the Transit secrets engine: the "wrapped" data key is only the
    plaintext data key with a version prefix, so it can be unwrapped again.
    """

    def __init__(self):
        self.version = 1
        self.data_keys = {}

    def datakey(self, request):
        data_key = os.urandom(32)
        ciphertext = f"vault:v{self.version}:{os.urandom(8).hex()}"
        self.data_keys[ciphertext] = data_key
        body = {
            "data": {
                "plaintext": base64.b64encode(data_key).decode(),
                "ciphertext": ciphertext,
            }
        }
        return 200, {}, json.dumps(body)

    def decrypt(self, request):
        ciphertext = json.loads(request.body)["ciphertext"]
        if ciphertext not in self.data_keys:
            return 400, {}, json.dumps({"errors": ["invalid ciphertext"]})
        plaintext = base64.b64encode(self.data_keys[ciphertext]).decode()
        return 200, {}, json.dumps({"data": {"plaintext": plaintext}})


@pytest.fixture
def transit_key():
    transit_key = FakeTransitKey()
    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        mock.add_callback(responses.POST, DATAKEY_URL, callback=transit_key.datakey)
        mock.add_callback(responses.POST, DECRYPT_URL, callback=transit_key.decrypt)
        transit_key.mock = mock
        yield transit_key


vault_settings = override_settings(
    BASEROW_ENCRYPTION_PROVIDER="hashicorp_vault",
    BASEROW_VAULT_ADDR=VAULT_ADDR,
    BASEROW_VAULT_TOKEN="s.test-token",
    BASEROW_VAULT_NAMESPACE="baserow-namespace",
)


@vault_settings
def test_values_are_encrypted_with_data_keys_generated_by_vault(transit_key):
    handler = EncryptionHandler()

    encrypted = handler.encrypt("secret")
    handler.encrypt("another secret")

    assert encrypted.split(":")[2] == "hashicorp_vault"
    # A single data key is generated for all the values of the process.
    datakey_calls = [
        call for call in transit_key.mock.calls if call.request.url == DATAKEY_URL
    ]
    assert len(datakey_calls) == 1
    assert datakey_calls[0].request.headers["X-Vault-Token"] == "s.test-token"
    assert datakey_calls[0].request.headers["X-Vault-Namespace"] == (
        "baserow-namespace"
    )

    # Another process only knows the wrapped data key and asks Vault to unwrap it,
    # once.
    keyring.reset()
    assert handler.decrypt(encrypted) == "secret"
    assert handler.decrypt(encrypted) == "secret"
    decrypt_calls = [
        call for call in transit_key.mock.calls if call.request.url == DECRYPT_URL
    ]
    assert len(decrypt_calls) == 1


@vault_settings
def test_vault_refusing_to_unwrap_the_data_key_is_a_decryption_error(transit_key):
    handler = EncryptionHandler()
    encrypted = handler.encrypt("secret")
    transit_key.data_keys.clear()
    keyring.reset()

    with pytest.raises(DecryptionError):
        handler.decrypt(encrypted)


@vault_settings
def test_values_must_be_reencrypted_after_rotating_the_transit_key(transit_key):
    handler = EncryptionHandler()
    encrypted = handler.encrypt("secret")
    assert not handler.needs_reencryption(encrypted)

    transit_key.version = 2
    keyring.reset()

    assert handler.needs_reencryption(encrypted)
    assert handler.decrypt(encrypted) == "secret"
    assert not handler.needs_reencryption(handler.encrypt("secret"))


def test_switching_from_local_keys_to_vault(transit_key):
    handler = EncryptionHandler()
    encrypted_locally = handler.encrypt("secret")

    with vault_settings:
        assert handler.decrypt(encrypted_locally) == "secret"
        assert handler.needs_reencryption(encrypted_locally)
        encrypted_by_vault = handler.encrypt("secret")
        assert not handler.needs_reencryption(encrypted_by_vault)

    # Vault values can't be read anymore when Vault isn't configured.
    with pytest.raises(DecryptionError):
        handler.decrypt(encrypted_by_vault)


@vault_settings
def test_vault_being_unreachable_is_a_key_provider_error():
    with responses.RequestsMock() as mock:
        mock.add(responses.POST, DATAKEY_URL, body=requests.ConnectionError("refused"))
        with pytest.raises(KeyProviderError):
            EncryptionHandler().encrypt("secret")


@override_settings(
    BASEROW_ENCRYPTION_PROVIDER="hashicorp_vault",
    BASEROW_VAULT_ADDR=VAULT_ADDR,
    BASEROW_VAULT_AUTH_METHOD="approle",
    BASEROW_VAULT_APPROLE_ROLE_ID="role-id",
    BASEROW_VAULT_APPROLE_SECRET_ID="secret-id",
)
def test_approle_authentication_logs_in_again_when_the_token_is_revoked(
    transit_key,
):
    login_url = f"{VAULT_ADDR}/v1/auth/approle/login"
    issued_tokens = iter(["s.first", "s.second"])

    def login(request):
        assert json.loads(request.body) == {
            "role_id": "role-id",
            "secret_id": "secret-id",
        }
        body = {"auth": {"client_token": next(issued_tokens), "lease_duration": 3600}}
        return 200, {}, json.dumps(body)

    transit_key.mock.add_callback(responses.POST, login_url, callback=login)
    handler = EncryptionHandler()
    encrypted = handler.encrypt("secret")

    # Vault revokes the first token, so the next request is denied once.
    transit_key.mock.remove(responses.POST, DECRYPT_URL)
    transit_key.mock.add(responses.POST, DECRYPT_URL, status=403)
    transit_key.mock.add_callback(
        responses.POST, DECRYPT_URL, callback=transit_key.decrypt
    )
    keyring._unwrapped.clear()

    assert handler.decrypt(encrypted) == "secret"
    tokens_used = [
        call.request.headers.get("X-Vault-Token")
        for call in transit_key.mock.calls
        if call.request.url != login_url
    ]
    assert tokens_used == ["s.first", "s.first", "s.second"]


def test_kubernetes_authentication_uses_the_service_account_token(
    transit_key, tmp_path
):
    service_account_token = tmp_path / "token"
    service_account_token.write_text("service-account-jwt\n")
    login_url = f"{VAULT_ADDR}/v1/auth/k8s-cluster/login"

    def login(request):
        assert json.loads(request.body) == {
            "role": "baserow",
            "jwt": "service-account-jwt",
        }
        body = {"auth": {"client_token": "s.k8s", "lease_duration": 600}}
        return 200, {}, json.dumps(body)

    transit_key.mock.add_callback(responses.POST, login_url, callback=login)

    with override_settings(
        BASEROW_ENCRYPTION_PROVIDER="hashicorp_vault",
        BASEROW_VAULT_ADDR=VAULT_ADDR,
        BASEROW_VAULT_AUTH_METHOD="kubernetes",
        BASEROW_VAULT_AUTH_MOUNT="k8s-cluster",
        BASEROW_VAULT_KUBERNETES_ROLE="baserow",
        BASEROW_VAULT_KUBERNETES_TOKEN_PATH=str(service_account_token),
    ):
        assert EncryptionHandler().encrypt("secret").split(":")[2] == (
            "hashicorp_vault"
        )

    assert transit_key.mock.calls[-1].request.headers["X-Vault-Token"] == "s.k8s"


def test_token_file_is_read_again_after_an_authentication_failure(
    transit_key, tmp_path
):
    token_file = tmp_path / "vault-token"
    token_file.write_text("s.expired")

    with override_settings(
        BASEROW_ENCRYPTION_PROVIDER="hashicorp_vault",
        BASEROW_VAULT_ADDR=VAULT_ADDR,
        BASEROW_VAULT_TOKEN_FILE=str(token_file),
    ):

        def renewed_by_the_vault_agent(request):
            token_file.write_text("s.renewed")
            return 403, {}, json.dumps({"errors": ["permission denied"]})

        transit_key.mock.remove(responses.POST, DATAKEY_URL)
        transit_key.mock.add_callback(
            responses.POST, DATAKEY_URL, callback=renewed_by_the_vault_agent
        )
        transit_key.mock.add_callback(
            responses.POST, DATAKEY_URL, callback=transit_key.datakey
        )

        EncryptionHandler().encrypt("secret")

    tokens_used = [
        call.request.headers["X-Vault-Token"] for call in transit_key.mock.calls
    ]
    assert tokens_used == ["s.expired", "s.renewed"]


@pytest.mark.parametrize(
    "vault_settings,message",
    [
        ({"BASEROW_VAULT_ADDR": "vault:8200"}, "BASEROW_VAULT_ADDR"),
        ({"BASEROW_VAULT_AUTH_METHOD": "ldap"}, "BASEROW_VAULT_AUTH_METHOD"),
        ({"BASEROW_VAULT_TOKEN": ""}, "BASEROW_VAULT_TOKEN"),
        (
            {"BASEROW_VAULT_AUTH_METHOD": "approle"},
            "BASEROW_VAULT_APPROLE_ROLE_ID",
        ),
        (
            {"BASEROW_VAULT_AUTH_METHOD": "kubernetes"},
            "BASEROW_VAULT_KUBERNETES_ROLE",
        ),
    ],
)
def test_invalid_vault_configuration(vault_settings, message):
    with override_settings(
        **{
            "BASEROW_ENCRYPTION_PROVIDER": "hashicorp_vault",
            "BASEROW_VAULT_ADDR": VAULT_ADDR,
            **vault_settings,
        }
    ):
        with pytest.raises(EncryptionConfigurationError, match=message):
            EncryptionHandler().encrypt("secret")
