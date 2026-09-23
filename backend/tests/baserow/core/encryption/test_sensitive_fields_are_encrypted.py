import re

from django.apps import apps

from baserow.core.encryption.fields import EncryptedFieldMixin

SENSITIVE_FIELD_NAME = re.compile(
    r"secret|passw|token|api_?key|private|credential|signature|session",
    re.IGNORECASE,
)

# Field names that look sensitive, but don't contain a secret.
NOT_SENSITIVE_FIELD_NAMES = {
    "access_token_url",
    "allow_reset_password",
    "encrypt_secrets_at_rest",
    "last_password_change",
    "use_id_token",
    "user_session_id",
    "verify_import_signature",
}

# Columns with a sensitive name that are deliberately not encrypted.
NOT_ENCRYPTED = {
    "auth.User.password": "Hashed by Django.",
    "database.View.public_view_password": "Hashed by Django.",
    "core.BlacklistedToken.hashed_token": "A hash that's looked up by value.",
    "core.Action.session": "The id of the client session, not a secret.",
    "sessions.Session.session_key": "Looked up by value.",
    "sessions.Session.session_data": "Signed by Django and short lived.",
    "integrations.CoreInboundEmailTriggerService.token": (
        "The local part of a shared email address that's looked up by value."
    ),
}

# Columns containing secrets without a sensitive name.
MUST_BE_ENCRYPTED = {
    "baserow_enterprise.AuditLogEntry.action_params",
    "core.MCPEndpoint.key",
    "core.TOTPAuthProviderModel.provisioning_qr_code",
    "core.TOTPAuthProviderModel.provisioning_url",
    "core.Workspace.generative_ai_models_settings",
    "database.TableWebhook.url",
    "database.TableWebhookCall.called_url",
    "database.TableWebhookCall.error",
    "database.TableWebhookCall.request",
    "database.TableWebhookCall.response",
    "database.TableWebhookHeader.value",
    "database.Token.key",
    "integrations.AIIntegration.ai_settings",
}


def get_concrete_fields():
    for model in apps.get_models():
        if model._meta.proxy or not model._meta.managed:
            continue
        for field in model._meta.local_concrete_fields:
            if not field.is_relation:
                yield f"{model._meta.label}.{field.name}", field


def test_columns_with_a_sensitive_name_are_encrypted():
    not_encrypted = sorted(
        label
        for label, field in get_concrete_fields()
        if SENSITIVE_FIELD_NAME.search(field.name)
        and field.name not in NOT_SENSITIVE_FIELD_NAMES
        and label not in NOT_ENCRYPTED
        and not isinstance(field, EncryptedFieldMixin)
    )

    assert not_encrypted == [], (
        "Store secrets in an EncryptedTextField or EncryptedJSONField, or add the "
        "column to NOT_ENCRYPTED with the reason it doesn't need to be encrypted."
    )


def test_known_secrets_are_encrypted():
    fields = dict(get_concrete_fields())
    installed = {config.label for config in apps.get_app_configs()}

    not_encrypted = sorted(
        label
        for label in MUST_BE_ENCRYPTED
        if label.split(".")[0] in installed
        and not isinstance(fields[label], EncryptedFieldMixin)
    )

    assert not_encrypted == []
