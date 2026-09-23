import pytest

from baserow.core.encryption.handler import EncryptionHandler


@pytest.mark.once_per_day_in_ci
def test_existing_keys_get_a_lookup_hash_and_stay_in_plain_text(migrator):
    """
    During a rolling upgrade the previous version still looks tokens up by their
    plain key, so the migration only adds the hash. The keys are encrypted later by
    the `encrypt_data` management command.
    """

    migrate_from = [
        ("database", "0223_gridview_group_by_layout"),
        ("core", "0121_agent"),
    ]
    migrate_to = [
        ("database", "0224_encrypt_secrets_at_rest"),
        ("core", "0122_encrypt_secrets_at_rest"),
    ]

    old_state = migrator.migrate(migrate_from)

    User = old_state.apps.get_model("auth", "User")
    Workspace = old_state.apps.get_model("core", "Workspace")
    Token = old_state.apps.get_model("database", "Token")
    MCPEndpoint = old_state.apps.get_model("core", "MCPEndpoint")

    user = User.objects.create(username="user@example.com", email="user@example.com")
    workspace = Workspace.objects.create(name="Workspace")
    Token.objects.create(
        name="Token", key="plain-token-key", user_id=user.id, workspace_id=workspace.id
    )
    MCPEndpoint.objects.create(
        name="MCP", key="plain-mcp-key", user_id=user.id, workspace_id=workspace.id
    )

    new_state = migrator.migrate(migrate_to)

    Token = new_state.apps.get_model("database", "Token")
    MCPEndpoint = new_state.apps.get_model("core", "MCPEndpoint")
    token = Token.objects.get()
    endpoint = MCPEndpoint.objects.get()

    assert token.key == "plain-token-key"
    assert token.key_hash == EncryptionHandler.hash_for_lookup("plain-token-key")
    assert endpoint.key == "plain-mcp-key"
    assert endpoint.key_hash == EncryptionHandler.hash_for_lookup("plain-mcp-key")
    assert Token.objects.filter(key_hash=token.key_hash).count() == 1

