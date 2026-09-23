import copy
import json
import pickle
from unittest.mock import Mock, patch

from django.apps.registry import Apps
from django.core import checks
from django.core.exceptions import FieldError
from django.db import models

import pytest

from baserow.contrib.database.webhooks.models import TableWebhookHeader
from baserow.contrib.integrations.core.models import SMTPIntegration
from baserow.contrib.integrations.slack.models import SlackBotIntegration
from baserow.core.encryption.exceptions import DecryptionError, KeyProviderError
from baserow.core.encryption.fields import (
    EncryptedJSONField,
    EncryptedStr,
    EncryptedTextField,
    UndecryptedValue,
)
from baserow.core.encryption.handler import (
    EncryptionHandler,
    forget_encryption_enabled,
    is_encryption_enabled,
    keyring,
)
from baserow.core.encryption.key_provider_types import LocalKeyProviderType
from baserow.core.models import Settings, Workspace


@pytest.mark.django_db
def test_secrets_are_stored_encrypted(data_fixture, stored_value):
    integration = data_fixture.create_slack_bot_integration(token="xoxb-secret")
    webhook = data_fixture.create_table_webhook(
        url="https://hooks.slack.com/services/T0/B0/secret-path",
        headers={"Authorization": "Bearer secret-header"},
    )
    header = webhook.headers.get()

    stored_token = stored_value(SlackBotIntegration, "token", integration.pk)
    stored_header = stored_value(TableWebhookHeader, "value", header.pk)
    stored_url = stored_value(type(webhook), "url", webhook.pk)

    for stored, plaintext in [
        (stored_token, "xoxb-secret"),
        (stored_header, "Bearer secret-header"),
        (stored_url, "https://hooks.slack.com/services/T0/B0/secret-path"),
    ]:
        assert EncryptionHandler.is_encrypted(stored)
        assert plaintext not in stored
        assert EncryptionHandler().decrypt(stored) == plaintext

    integration.refresh_from_db()
    assert integration.token == "xoxb-secret"
    assert webhook.header_dict == {"Authorization": "Bearer secret-header"}
    assert list(
        SlackBotIntegration.objects.filter(pk=integration.pk).values_list(
            "token", flat=True
        )
    ) == ["xoxb-secret"]


@pytest.mark.django_db
def test_values_stored_before_the_column_was_encrypted_are_still_readable(
    data_fixture, stored_value, store_raw_value
):
    integration = data_fixture.create_smtp_integration(password="new")
    store_raw_value(SMTPIntegration, "password", integration.pk, "legacy")

    integration.refresh_from_db()
    assert integration.password == "legacy"

    integration.save()
    assert EncryptionHandler.is_encrypted(
        stored_value(SMTPIntegration, "password", integration.pk)
    )


@pytest.mark.django_db
def test_empty_values_are_stored_as_they_are(data_fixture, stored_value):
    without_password = data_fixture.create_smtp_integration(password=None)
    empty_password = data_fixture.create_smtp_integration(password="")
    workspace = data_fixture.create_workspace()

    assert stored_value(SMTPIntegration, "password", without_password.pk) is None
    assert stored_value(SMTPIntegration, "password", empty_password.pk) == ""
    assert stored_value(Workspace, "generative_ai_models_settings", workspace.pk) == {}


@pytest.mark.django_db
def test_encrypted_json_field(data_fixture, stored_value, store_raw_value):
    settings = {"openai": {"api_key": "sk-secret", "models": ["gpt-4o"]}}
    workspace = data_fixture.create_workspace()
    workspace.generative_ai_models_settings = settings
    workspace.save()

    stored = stored_value(Workspace, "generative_ai_models_settings", workspace.pk)
    assert EncryptionHandler.is_encrypted(stored)
    assert "sk-secret" not in stored

    workspace.refresh_from_db()
    assert workspace.generative_ai_models_settings == settings

    store_raw_value(
        Workspace,
        "generative_ai_models_settings",
        workspace.pk,
        json.dumps({"legacy": {"api_key": "sk-legacy"}}),
    )
    workspace.refresh_from_db()
    assert workspace.generative_ai_models_settings == {
        "legacy": {"api_key": "sk-legacy"}
    }


@pytest.mark.django_db
def test_encrypted_fields_cannot_be_filtered_by_value(data_fixture):
    integration = data_fixture.create_smtp_integration(password="")

    with pytest.raises(FieldError, match="encrypted"):
        list(SMTPIntegration.objects.filter(password="secret"))
    with pytest.raises(FieldError):
        list(SMTPIntegration.objects.filter(password__icontains="secret"))
    with pytest.raises(FieldError):
        list(SMTPIntegration.objects.filter(password__in=["secret"]))
    with pytest.raises(FieldError):
        list(Workspace.objects.filter(generative_ai_models_settings__openai="x"))
    with pytest.raises(FieldError):
        list(Workspace.objects.filter(generative_ai_models_settings={"a": 1}))

    assert list(SMTPIntegration.objects.filter(password="")) == [integration]
    assert list(SMTPIntegration.objects.filter(password__isnull=True)) == []
    assert Workspace.objects.filter(
        generative_ai_models_settings__isnull=False
    ).exists()


def test_encrypted_fields_cannot_be_unique_or_indexed():
    class ModelWithUniqueEncryptedField(models.Model):
        unique_secret = EncryptedTextField(unique=True)
        indexed_secret = EncryptedTextField(db_index=True)
        secret = EncryptedTextField()
        settings = EncryptedJSONField(default=dict)

        class Meta:
            apps = Apps()
            app_label = "encryption_tests"

    errors = [
        error
        for field in ModelWithUniqueEncryptedField._meta.get_fields()
        for error in field.check()
    ]

    assert [(error.id, error.obj.name) for error in errors] == [
        ("baserow.encryption.E001", "unique_secret"),
        ("baserow.encryption.E001", "indexed_secret"),
    ]
    assert all(isinstance(error, checks.Error) for error in errors)


@pytest.mark.django_db
def test_saving_an_unchanged_secret_keeps_the_stored_ciphertext(
    data_fixture, stored_value
):
    integration = data_fixture.create_slack_bot_integration(token="xoxb-secret")
    stored = stored_value(SlackBotIntegration, "token", integration.pk)

    integration.refresh_from_db()
    integration.name = "Renamed"
    integration.save()
    assert stored_value(SlackBotIntegration, "token", integration.pk) == stored

    integration.token = "xoxb-changed"
    integration.save()
    changed = stored_value(SlackBotIntegration, "token", integration.pk)
    assert changed != stored
    assert EncryptionHandler().decrypt(changed) == "xoxb-changed"


@pytest.mark.django_db
def test_values_are_written_in_plain_text_until_encryption_is_enabled(
    data_fixture, stored_value, encryption_at_rest_disabled
):
    """
    The previous version, which keeps running during a rolling upgrade, must be able
    to read everything the new version writes.
    """

    integration = data_fixture.create_slack_bot_integration(token="xoxb-secret")
    workspace = data_fixture.create_workspace()
    workspace.generative_ai_models_settings = {"openai": {"api_key": "sk-secret"}}
    workspace.save()

    assert stored_value(SlackBotIntegration, "token", integration.pk) == "xoxb-secret"
    assert stored_value(Workspace, "generative_ai_models_settings", workspace.pk) == {
        "openai": {"api_key": "sk-secret"}
    }

    integration.refresh_from_db()
    integration.save()
    assert stored_value(SlackBotIntegration, "token", integration.pk) == "xoxb-secret"


@pytest.mark.django_db
def test_encryption_enabled_is_read_from_the_settings(encryption_at_rest_disabled):
    assert not is_encryption_enabled()

    Settings.objects.update(encrypt_secrets_at_rest=True)
    forget_encryption_enabled()
    assert is_encryption_enabled()

    # A new instance, before its settings are created, encrypts from the start.
    Settings.objects.all().delete()
    forget_encryption_enabled()
    assert is_encryption_enabled()


@pytest.mark.django_db
def test_legacy_values_are_encrypted_when_saved_once_encryption_is_enabled(
    data_fixture, stored_value, store_raw_value
):
    integration = data_fixture.create_slack_bot_integration()
    store_raw_value(SlackBotIntegration, "token", integration.pk, "xoxb-legacy")

    integration.refresh_from_db()
    integration.save()

    stored = stored_value(SlackBotIntegration, "token", integration.pk)
    assert EncryptionHandler().decrypt(stored) == "xoxb-legacy"
    assert stored != "xoxb-legacy"


@pytest.mark.django_db
def test_decrypted_values_are_pickled_and_copied_as_plain_strings(data_fixture):
    integration = data_fixture.create_slack_bot_integration(token="xoxb-secret")
    integration.refresh_from_db()

    assert isinstance(integration.token, EncryptedStr)
    for copied in [
        pickle.loads(pickle.dumps(integration.token)),  # noqa: S301
        copy.deepcopy(integration.token),
        pickle.loads(pickle.dumps(integration)).token,  # noqa: S301
    ]:
        assert copied == "xoxb-secret"
        assert type(copied) is str


def key_provider_unreachable():
    """Like a process that starts while HashiCorp Vault is unreachable."""

    keyring.reset()
    error = KeyProviderError("The key provider is unreachable.")
    return patch.multiple(
        LocalKeyProviderType,
        unwrap_data_key=Mock(side_effect=error),
        generate_data_key=Mock(side_effect=error),
    )


def value_cannot_be_decrypted():
    """Like a value whose key was removed."""

    return patch.object(
        EncryptionHandler, "decrypt", side_effect=DecryptionError("Unknown key.")
    )


@pytest.mark.django_db
@pytest.mark.parametrize(
    "cannot_decrypt,error",
    [
        (key_provider_unreachable, KeyProviderError),
        (value_cannot_be_decrypted, DecryptionError),
    ],
)
def test_rows_are_loaded_and_saved_when_a_secret_cannot_be_decrypted(
    data_fixture, stored_value, cannot_decrypt, error
):
    """
    A workspace is loaded by almost every request, but its generative AI settings
    are only needed by the AI features, so only those fail.
    """

    workspace = data_fixture.create_workspace(name="Workspace")
    workspace.generative_ai_models_settings = {"openai": {"api_key": "sk-secret"}}
    workspace.save()
    integration = data_fixture.create_slack_bot_integration(token="xoxb-secret")
    stored_settings = stored_value(
        Workspace, "generative_ai_models_settings", workspace.id
    )
    stored_token = stored_value(SlackBotIntegration, "token", integration.id)

    with cannot_decrypt():
        workspace = Workspace.objects.get(id=workspace.id)
        integration = SlackBotIntegration.objects.get(id=integration.id)

        assert workspace.name == "Workspace"
        with pytest.raises(error):
            workspace.generative_ai_models_settings
        with pytest.raises(error):
            integration.token
        assert isinstance(
            SlackBotIntegration.objects.values_list("token", flat=True).get(
                id=integration.id
            ),
            UndecryptedValue,
        )

        workspace.name = "Renamed"
        workspace.save()
        integration.name = "Renamed"
        integration.save()

    assert stored_value(Workspace, "generative_ai_models_settings", workspace.id) == (
        stored_settings
    )
    assert stored_value(SlackBotIntegration, "token", integration.id) == stored_token
    # Decrypted as soon as it's possible again.
    assert workspace.generative_ai_models_settings == {
        "openai": {"api_key": "sk-secret"}
    }
    assert integration.token == "xoxb-secret"
    workspace.refresh_from_db()
    assert workspace.name == "Renamed"


@pytest.mark.django_db
def test_saving_unchanged_json_keeps_the_stored_ciphertext(data_fixture, stored_value):
    workspace = data_fixture.create_workspace()
    workspace.generative_ai_models_settings = {"openai": {"api_key": "sk-secret"}}
    workspace.save()
    stored = stored_value(Workspace, "generative_ai_models_settings", workspace.id)

    workspace = Workspace.objects.get(id=workspace.id)
    workspace.save()
    assert stored_value(Workspace, "generative_ai_models_settings", workspace.id) == (
        stored
    )

    # Changed in place.
    workspace.generative_ai_models_settings["openai"]["api_key"] = "sk-changed"
    workspace.save()
    changed = stored_value(Workspace, "generative_ai_models_settings", workspace.id)
    assert changed != stored
    assert json.loads(EncryptionHandler().decrypt(changed)) == {
        "openai": {"api_key": "sk-changed"}
    }
    workspace.refresh_from_db()
    assert workspace.generative_ai_models_settings == {
        "openai": {"api_key": "sk-changed"}
    }
    assert pickle.loads(pickle.dumps(workspace.generative_ai_models_settings)) == {  # noqa: S301
        "openai": {"api_key": "sk-changed"}
    }
