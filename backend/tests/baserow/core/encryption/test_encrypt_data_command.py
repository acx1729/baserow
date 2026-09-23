import json
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

import pytest

from baserow.contrib.database.tokens.handler import TokenHandler
from baserow.contrib.database.tokens.models import Token
from baserow.contrib.integrations.slack.models import SlackBotIntegration
from baserow.core.encryption.exceptions import KeyProviderError
from baserow.core.encryption.handler import (
    ENCRYPTION_ENABLED_RECHECK_SECONDS,
    EncryptionHandler,
    is_encryption_enabled,
)
from baserow.core.encryption.key_provider_types import (
    LocalKeyProviderType,
    decode_encryption_key,
    generate_encryption_key,
)
from baserow.core.models import Settings, Workspace


def run_encrypt_data(*args):
    out = StringIO()
    call_command("encrypt_data", *args, stdout=out)
    return out.getvalue()


@pytest.mark.django_db
def test_encrypt_data_encrypts_the_values_stored_in_plain_text(
    data_fixture, stored_value, store_raw_value
):
    integration = data_fixture.create_slack_bot_integration(token="xoxb-new")
    store_raw_value(SlackBotIntegration, "token", integration.pk, "xoxb-legacy")
    workspace = data_fixture.create_workspace()
    store_raw_value(
        Workspace,
        "generative_ai_models_settings",
        workspace.pk,
        json.dumps({"openai": {"api_key": "sk-legacy"}}),
    )
    # The previous version stored the plain key without hash.
    token = data_fixture.create_token()
    store_raw_value(Token, "key", token.pk, "legacy-token-key")
    store_raw_value(Token, "key_hash", token.pk, None)

    output = run_encrypt_data("--dry-run")

    assert "integrations.SlackBotIntegration.token: 1 values, 1 to encrypt" in output
    assert "core.Workspace.generative_ai_models_settings: 1 values, 1 to encrypt" in (
        output
    )
    assert "database.Token.key: 1 values, 1 to encrypt" in output
    assert "3 values must be encrypted." in output
    assert stored_value(SlackBotIntegration, "token", integration.pk) == "xoxb-legacy"

    output = run_encrypt_data()

    assert "Encrypted 3 values." in output
    stored_token = stored_value(SlackBotIntegration, "token", integration.pk)
    stored_settings = stored_value(
        Workspace, "generative_ai_models_settings", workspace.pk
    )
    stored_key = stored_value(Token, "key", token.pk)
    assert all(
        EncryptionHandler.is_encrypted(value)
        for value in [stored_token, stored_settings, stored_key]
    )
    integration.refresh_from_db()
    workspace.refresh_from_db()
    assert integration.token == "xoxb-legacy"
    assert workspace.generative_ai_models_settings == {
        "openai": {"api_key": "sk-legacy"}
    }
    # The lookup hash is computed before the key is encrypted, so the token keeps
    # working.
    assert stored_value(Token, "key_hash", token.pk) == (
        EncryptionHandler.hash_for_lookup("legacy-token-key")
    )
    assert TokenHandler().get_by_key("legacy-token-key").id == token.id

    assert "0 values must be encrypted." in run_encrypt_data("--dry-run")


@pytest.mark.django_db
def test_encrypt_data_reencrypts_the_values_after_a_key_rotation(data_fixture):
    old_key, new_key = generate_encryption_key(), generate_encryption_key()

    with override_settings(BASEROW_ENCRYPTION_KEYS=[old_key]):
        integration = data_fixture.create_slack_bot_integration(token="xoxb-secret")

    with override_settings(BASEROW_ENCRYPTION_KEYS=[new_key, old_key]):
        assert "integrations.SlackBotIntegration.token: 1 values, 1 encrypted" in (
            run_encrypt_data()
        )

    with override_settings(BASEROW_ENCRYPTION_KEYS=[new_key]):
        integration.refresh_from_db()
        assert integration.token == "xoxb-secret"


@pytest.mark.django_db
def test_encrypt_data_reports_the_values_that_cant_be_decrypted(
    data_fixture, stored_value, store_raw_value
):
    with override_settings(BASEROW_ENCRYPTION_KEYS=[generate_encryption_key()]):
        lost = data_fixture.create_slack_bot_integration(token="lost")
    legacy = data_fixture.create_slack_bot_integration()
    store_raw_value(SlackBotIntegration, "token", legacy.pk, "xoxb-legacy")

    out = StringIO()
    with pytest.raises(SystemExit):
        call_command("encrypt_data", stdout=out)

    assert (
        "integrations.SlackBotIntegration.token: 2 values, 1 encrypted, "
        "1 could not be decrypted"
    ) in out.getvalue()
    assert EncryptionHandler.is_encrypted(
        stored_value(SlackBotIntegration, "token", legacy.pk)
    )
    assert stored_value(SlackBotIntegration, "token", lost.pk).startswith("bxenc:")


def test_generate_encryption_key_command():
    out = StringIO()
    call_command("generate_encryption_key", stdout=out)

    assert len(decode_encryption_key(out.getvalue().strip())) == 32


@pytest.mark.django_db
@patch("baserow.core.management.commands.encrypt_data.time.sleep")
def test_encrypt_data_enables_encryption_after_an_upgrade(
    mock_sleep, data_fixture, stored_value, encryption_at_rest_disabled
):
    integration = data_fixture.create_slack_bot_integration(token="xoxb-secret")
    assert stored_value(SlackBotIntegration, "token", integration.pk) == ("xoxb-secret")

    output = run_encrypt_data("--dry-run")
    assert "Encryption at rest isn't enabled yet" in output
    assert not Settings.objects.get().encrypt_secrets_at_rest

    output = run_encrypt_data()

    assert "Encryption at rest is enabled." in output
    assert "integrations.SlackBotIntegration.token: 1 values, 1 encrypted" in output
    assert Settings.objects.get().encrypt_secrets_at_rest
    assert is_encryption_enabled()
    # The second pass runs after every process noticed that encryption is enabled.
    mock_sleep.assert_called_once_with(ENCRYPTION_ENABLED_RECHECK_SECONDS)
    assert EncryptionHandler.is_encrypted(
        stored_value(SlackBotIntegration, "token", integration.pk)
    )

    new_integration = data_fixture.create_slack_bot_integration(token="xoxb-new")
    assert EncryptionHandler.is_encrypted(
        stored_value(SlackBotIntegration, "token", new_integration.pk)
    )


@pytest.mark.django_db
def test_encrypt_data_does_not_enable_encryption_when_the_key_provider_fails(
    data_fixture, stored_value, encryption_at_rest_disabled
):
    integration = data_fixture.create_slack_bot_integration(token="xoxb-secret")

    for method in ["generate_data_key", "unwrap_data_key"]:
        with patch.object(
            LocalKeyProviderType,
            method,
            side_effect=KeyProviderError("Vault is unreachable."),
        ):
            with pytest.raises(CommandError, match="nothing has been changed"):
                run_encrypt_data()
            with pytest.raises(CommandError, match="nothing has been changed"):
                run_encrypt_data("--if-not-enabled")

    assert not Settings.objects.get().encrypt_secrets_at_rest
    assert not is_encryption_enabled()
    assert stored_value(SlackBotIntegration, "token", integration.pk) == "xoxb-secret"


@pytest.mark.django_db
def test_encrypt_data_if_not_enabled_does_nothing_once_enabled(
    data_fixture, store_raw_value
):
    integration = data_fixture.create_slack_bot_integration()
    store_raw_value(SlackBotIntegration, "token", integration.pk, "xoxb-legacy")

    assert "already enabled" in run_encrypt_data("--if-not-enabled")
    assert "1 values must be encrypted." in run_encrypt_data("--dry-run")


@pytest.mark.django_db
def test_encrypt_data_does_not_overwrite_a_value_changed_concurrently(
    data_fixture, stored_value, store_raw_value
):
    integration = data_fixture.create_slack_bot_integration()
    store_raw_value(SlackBotIntegration, "token", integration.pk, "xoxb-read")
    field = SlackBotIntegration._meta.get_field("token")

    # The value changed after the command read it.
    store_raw_value(SlackBotIntegration, "token", integration.pk, "xoxb-changed")
    rewritten = EncryptionHandler()._rewrite_values(
        SlackBotIntegration, integration.pk, {field: ("xoxb-read", "xoxb-read")}
    )

    assert not rewritten
    assert stored_value(SlackBotIntegration, "token", integration.pk) == (
        "xoxb-changed"
    )
