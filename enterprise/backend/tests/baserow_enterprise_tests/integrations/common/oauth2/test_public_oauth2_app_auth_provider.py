from unittest.mock import patch

import pytest

from baserow.contrib.builder.api.domains.serializers import (
    PublicPolymorphicAppAuthProviderSerializer,
)
from baserow.core.app_auth_providers.models import AppAuthProvider
from baserow.core.encryption.exceptions import DecryptionError
from baserow.core.encryption.handler import EncryptionHandler
from baserow_enterprise.integrations.common.sso.oauth2.models import (
    OpenIdConnectAppAuthProviderModel,
)


@pytest.mark.django_db
def test_public_serializer_does_not_decrypt_the_secret(data_fixture):
    provider = data_fixture.create_app_auth_provider(
        OpenIdConnectAppAuthProviderModel,
        name="OIDC",
        base_url="https://idp.example.com",
        client_id="client_id",
        secret="secret",
    )
    base_provider = AppAuthProvider.objects.get(id=provider.id)

    # Published applications are public and must work even when the key provider is
    # unavailable, the secret is never part of the public representation.
    with patch.object(
        EncryptionHandler, "decrypt", side_effect=DecryptionError("unavailable")
    ):
        data = PublicPolymorphicAppAuthProviderSerializer(base_provider).data

    assert data["name"] == "OIDC"
    assert data["base_url"] == "https://idp.example.com"
    assert "secret" not in data
