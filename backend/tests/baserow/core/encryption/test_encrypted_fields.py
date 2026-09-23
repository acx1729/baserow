import json

from django.apps.registry import Apps
from django.core import checks
from django.core.exceptions import FieldError
from django.db import models

import pytest

from baserow.contrib.database.webhooks.models import TableWebhookHeader
from baserow.contrib.integrations.core.models import SMTPIntegration
from baserow.contrib.integrations.slack.models import SlackBotIntegration
from baserow.core.encryption.fields import EncryptedJSONField, EncryptedTextField
from baserow.core.encryption.handler import EncryptionHandler
from baserow.core.models import Workspace


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
