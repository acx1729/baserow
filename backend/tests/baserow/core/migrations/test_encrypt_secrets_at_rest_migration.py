from django.db import connection

import pytest

from baserow.core.encryption.handler import EncryptionHandler

MIGRATE_FROM = [
    ("database", "0212_data_sync_delete_unmatched_rows"),
    ("core", "0114_alter_workspaceinvitation_message"),
    ("integrations", "0031_corestartworkflowservice"),
    ("baserow_enterprise", "0062_core_xls_file_reader"),
]
MIGRATE_TO = [
    ("database", "0213_encrypt_secrets_at_rest"),
    ("core", "0115_encrypt_secrets_at_rest"),
    ("integrations", "0032_encrypt_secrets_at_rest"),
    ("baserow_enterprise", "0063_encrypt_secrets_at_rest"),
]


@pytest.mark.once_per_day_in_ci
def test_existing_keys_get_a_lookup_hash_and_stay_in_plain_text(migrator):
    """
    During a rolling upgrade the previous version still looks tokens up by their
    plain key, so the migration only adds the hash. The keys are encrypted later by
    the `encrypt_data` management command.
    """

    migrate_from = MIGRATE_FROM
    migrate_to = MIGRATE_TO

    old_state = migrator.migrate(migrate_from)

    User = old_state.apps.get_model("auth", "User")
    Settings = old_state.apps.get_model("core", "Settings")
    Workspace = old_state.apps.get_model("core", "Workspace")
    Token = old_state.apps.get_model("database", "Token")
    MCPEndpoint = old_state.apps.get_model("core", "MCPEndpoint")

    Settings.objects.get_or_create()
    user = User.objects.create(username="user@example.com", email="user@example.com")
    workspace = Workspace.objects.create(name="Workspace")
    Token.objects.create(
        name="Token", key="plain-token-key", user_id=user.id, workspace_id=workspace.id
    )
    MCPEndpoint.objects.create(
        name="MCP", key="plain-mcp-key", user_id=user.id, workspace_id=workspace.id
    )

    new_state = migrator.migrate(migrate_to)

    Settings = new_state.apps.get_model("core", "Settings")
    Token = new_state.apps.get_model("database", "Token")
    MCPEndpoint = new_state.apps.get_model("core", "MCPEndpoint")

    # The existing instance keeps writing in plain text until `encrypt_data` runs.
    assert set(Settings.objects.values_list("encrypt_secrets_at_rest", flat=True)) == {
        False
    }
    token = Token.objects.get()
    endpoint = MCPEndpoint.objects.get()

    assert token.key == "plain-token-key"
    assert token.key_hash == EncryptionHandler.hash_for_lookup("plain-token-key")
    assert endpoint.key == "plain-mcp-key"
    assert endpoint.key_hash == EncryptionHandler.hash_for_lookup("plain-mcp-key")
    assert Token.objects.filter(key_hash=token.key_hash).count() == 1



@pytest.mark.once_per_day_in_ci
def test_upgrading_from_a_release_that_encryption_at_rest_was_backported_to(
    migrator,
):
    """
    The migrations of a release that encryption at rest was backported to have other
    names, but made the same changes. Upgrading from it must not fail, and must not
    disable encryption again.
    """

    old_state = migrator.migrate(MIGRATE_FROM)
    User = old_state.apps.get_model("auth", "User")
    Settings = old_state.apps.get_model("core", "Settings")
    Workspace = old_state.apps.get_model("core", "Workspace")
    Token = old_state.apps.get_model("database", "Token")
    Settings.objects.get_or_create()
    user = User.objects.create(username="backport@example.com", email="backport@example.com")
    workspace = Workspace.objects.create(name="Workspace")
    token = Token.objects.create(
        name="Token", key="backport-token-key", user_id=user.id, workspace_id=workspace.id
    )

    # The backported migrations ran, and `encrypt_data` enabled encryption.
    migrator.migrate(MIGRATE_TO)
    encrypted_key = EncryptionHandler().encrypt("backport-token-key")
    with connection.cursor() as cursor:
        cursor.execute("UPDATE core_settings SET encrypt_secrets_at_rest = true")
        cursor.execute(
            "UPDATE database_token SET key = %s WHERE id = %s",
            [encrypted_key, token.id],
        )
        # This release doesn't know the names of the backported migrations.
        for app, name in MIGRATE_TO:
            cursor.execute(
                "DELETE FROM django_migrations WHERE app = %s AND name = %s",
                [app, name],
            )

    new_state = migrator.migrate(MIGRATE_TO)

    Settings = new_state.apps.get_model("core", "Settings")
    Token = new_state.apps.get_model("database", "Token")
    assert set(Settings.objects.values_list("encrypt_secrets_at_rest", flat=True)) == {
        True
    }
    token = Token.objects.get(id=token.id)
    assert token.key == "backport-token-key"
    assert token.key_hash == EncryptionHandler.hash_for_lookup("backport-token-key")
    with connection.cursor() as cursor:
        cursor.execute("SELECT key FROM database_token WHERE id = %s", [token.id])
        assert cursor.fetchone()[0] == encrypted_key
