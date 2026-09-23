import json
import uuid
from unittest.mock import patch

from django.db import connection

import pytest

from baserow.core.action.handler import ActionHandler
from baserow.core.action.models import Action
from baserow.core.action.scopes import ApplicationActionScopeType
from baserow.core.encryption.handler import EncryptionHandler
from baserow.core.user_sources.actions import UpdateUserSourceActionType
from baserow.core.user_sources.handler import UserSourceHandler
from baserow.core.user_sources.registries import user_source_type_registry
from baserow.core.user_sources.service import UserSourceService
from baserow_enterprise.integrations.common.sso.oauth2.models import (
    OpenIdConnectAppAuthProviderModel,
)
from baserow_enterprise.integrations.local_baserow.models import (
    LocalBaserowPasswordAppAuthProvider,
)
from baserow_enterprise.sso.oauth2.auth_provider_types import (
    OpenIdConnectAuthProviderTypeMixin,
    WellKnownUrls,
)


@pytest.mark.django_db
@pytest.mark.undo_redo
def test_update_user_source_auth_providers_undo_redo(data_fixture):
    session_id = str(uuid.uuid4())
    user = data_fixture.create_user(session_id=session_id)
    workspace = data_fixture.create_workspace(user=user)
    application = data_fixture.create_builder_application(workspace=workspace)
    database = data_fixture.create_database_application(workspace=workspace)
    integration = data_fixture.create_local_baserow_integration(
        application=application, user=user
    )
    table, fields, _ = data_fixture.build_table(
        user=user,
        database=database,
        columns=[
            ("Email", "text"),
            ("Password A", "password"),
            ("Password B", "password"),
        ],
        rows=[["a@baserow.io", "x", "y"]],
    )
    email_field, password_a, password_b = fields

    user_source_type = user_source_type_registry.get("local_baserow")
    user_source = UserSourceService().create_user_source(
        user,
        user_source_type,
        application,
        name="US",
        integration_id=integration.id,
        table_id=table.id,
        email_field_id=email_field.id,
        auth_providers=[
            {"type": "local_baserow_password", "password_field_id": password_a.id},
        ],
    )

    def current_password_field_id():
        return LocalBaserowPasswordAppAuthProvider.objects.get(
            user_source=user_source
        ).password_field_id

    assert current_password_field_id() == password_a.id

    user_source_for_update = UserSourceHandler().get_user_source_for_update(
        user_source.id
    )
    UpdateUserSourceActionType.do(
        user,
        user_source_for_update,
        auth_providers=[
            {"type": "local_baserow_password", "password_field_id": password_b.id},
        ],
    )
    assert current_password_field_id() == password_b.id

    scope = [ApplicationActionScopeType.value(application.id)]

    ActionHandler.undo(user, scope, session_id)
    # The password field must be restored to its original value.
    assert current_password_field_id() == password_a.id

    ActionHandler.redo(user, scope, session_id)
    assert current_password_field_id() == password_b.id


@pytest.mark.django_db
@pytest.mark.undo_redo
@patch.object(
    OpenIdConnectAuthProviderTypeMixin,
    "get_wellknown_urls",
    return_value=WellKnownUrls(
        authorization_url="https://idp.example.com/authorize",
        access_token_url="https://idp.example.com/token",
        user_info_url="https://idp.example.com/userinfo",
        jwks_url="https://idp.example.com/jwks",
        issuer="https://idp.example.com",
    ),
)
def test_update_user_source_openid_connect_secret_undo_redo(
    mock_get_wellknown_urls, data_fixture
):
    session_id = str(uuid.uuid4())
    user = data_fixture.create_user(session_id=session_id)
    workspace = data_fixture.create_workspace(user=user)
    application = data_fixture.create_builder_application(workspace=workspace)
    database = data_fixture.create_database_application(workspace=workspace)
    integration = data_fixture.create_local_baserow_integration(
        application=application, user=user
    )
    table, fields, _ = data_fixture.build_table(
        user=user,
        database=database,
        columns=[("Email", "text")],
        rows=[["a@baserow.io"]],
    )

    def openid_connect(secret):
        return {
            "type": "openid_connect",
            "name": "IdP",
            "base_url": "https://idp.example.com",
            "client_id": "client-id",
            "secret": secret,
        }

    user_source = UserSourceService().create_user_source(
        user,
        user_source_type_registry.get("local_baserow"),
        application,
        name="US",
        integration_id=integration.id,
        table_id=table.id,
        email_field_id=fields[0].id,
        auth_providers=[openid_connect("old-secret")],
    )

    def current_secret():
        provider = OpenIdConnectAppAuthProviderModel.objects.get(
            user_source=user_source
        )
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT secret FROM {provider._meta.db_table} "
                f"WHERE {provider._meta.pk.column} = %s",
                [provider.pk],
            )
            assert EncryptionHandler.is_encrypted(cursor.fetchone()[0])
        return provider.secret

    UpdateUserSourceActionType.do(
        user,
        UserSourceHandler().get_user_source_for_update(user_source.id),
        auth_providers=[openid_connect("new-secret")],
    )
    assert current_secret() == "new-secret"

    # The undo history is stored in the database too, the secrets are encrypted.
    stored_params = json.dumps(
        Action.objects.get(type=UpdateUserSourceActionType.type).params
    )
    assert "old-secret" not in stored_params
    assert "new-secret" not in stored_params

    scope = [ApplicationActionScopeType.value(application.id)]
    ActionHandler.undo(user, scope, session_id)
    assert current_secret() == "old-secret"

    ActionHandler.redo(user, scope, session_id)
    assert current_secret() == "new-secret"
