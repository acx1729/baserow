from django.db import connection, transaction

import pytest
from asgiref.sync import async_to_sync

from baserow.contrib.database.tokens.exceptions import TokenDoesNotExist
from baserow.contrib.database.tokens.handler import TokenHandler
from baserow.contrib.database.tokens.models import Token
from baserow.core.encryption.handler import EncryptionHandler
from baserow.core.encryption.utils import get_by_lookup_hash
from baserow.core.mcp import BaserowMCPServer, current_key
from baserow.core.mcp.handler import MCPEndpointHandler
from baserow.core.mcp.models import MCPEndpoint


def store_like_previous_version(model, pk, key):
    """The previous version stored the plain key and no hash."""

    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE {model._meta.db_table} SET key = %s, key_hash = NULL "
            f"WHERE id = %s",
            [key, pk],
        )


@pytest.mark.django_db
def test_token_key_is_encrypted_and_found_by_hash(data_fixture):
    token = data_fixture.create_token()

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT key, key_hash FROM database_token WHERE id = %s", [token.id]
        )
        stored_key, stored_hash = cursor.fetchone()

    assert EncryptionHandler.is_encrypted(stored_key)
    assert token.key not in stored_key
    assert stored_hash == EncryptionHandler.hash_for_lookup(token.key)
    assert TokenHandler().get_by_key(token.key).id == token.id

    with pytest.raises(TokenDoesNotExist):
        TokenHandler().get_by_key("does-not-exist")


@pytest.mark.django_db
def test_rotating_the_token_key_invalidates_the_old_key(data_fixture):
    user = data_fixture.create_user()
    token = data_fixture.create_token(user=user)
    old_key = token.key

    TokenHandler().rotate_token_key(user, token)

    assert TokenHandler().get_by_key(token.key).id == token.id
    with pytest.raises(TokenDoesNotExist):
        TokenHandler().get_by_key(old_key)


@pytest.mark.django_db
def test_saving_the_key_with_update_fields_updates_the_hash(data_fixture):
    token = data_fixture.create_token()
    token.key = "a" * 32
    token.save(update_fields=["key"])

    assert Token.objects.get(id=token.id).key_hash == (
        EncryptionHandler.hash_for_lookup("a" * 32)
    )


@pytest.mark.django_db
def test_keys_stored_by_the_previous_version_are_found_and_get_a_hash(data_fixture):
    token = data_fixture.create_token()
    store_like_previous_version(Token, token.id, "legacy-key")

    found = get_by_lookup_hash(Token.objects.all(), "legacy-key")

    assert found.id == token.id
    assert found.key == "legacy-key"
    assert Token.objects.get(id=token.id).key_hash == (
        EncryptionHandler.hash_for_lookup("legacy-key")
    )
    with pytest.raises(Token.DoesNotExist):
        get_by_lookup_hash(Token.objects.all(), "another-key")


@pytest.mark.django_db
def test_mcp_server_finds_the_endpoint_by_hashed_key(data_fixture):
    endpoint = data_fixture.create_mcp_endpoint()
    legacy_endpoint = data_fixture.create_mcp_endpoint()
    store_like_previous_version(MCPEndpoint, legacy_endpoint.id, "legacy-mcp-key")

    assert MCPEndpointHandler().get_by_key(endpoint.key).id == endpoint.id

    async def get_endpoint(key):
        current_key.set(key)
        return await BaserowMCPServer().get_endpoint()

    with transaction.atomic():
        assert async_to_sync(get_endpoint)(endpoint.key).id == endpoint.id
        assert async_to_sync(get_endpoint)("legacy-mcp-key").id == legacy_endpoint.id
        assert async_to_sync(get_endpoint)("unknown") is None
