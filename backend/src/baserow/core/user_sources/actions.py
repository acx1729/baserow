from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _

from baserow.core.action.models import Action
from baserow.core.action.registries import ActionTypeDescription, UndoableActionType
from baserow.core.action.scopes import ApplicationActionScopeType
from baserow.core.app_auth_providers.registries import app_auth_provider_type_registry
from baserow.core.encryption.fields import EncryptedTextField
from baserow.core.encryption.handler import EncryptionHandler, is_encryption_enabled
from baserow.core.models import Application
from baserow.core.trash.handler import TrashHandler
from baserow.core.user_sources.handler import UserSourceHandler
from baserow.core.user_sources.models import UserSource
from baserow.core.user_sources.registries import UserSourceType
from baserow.core.user_sources.service import UserSourceService
from baserow.core.user_sources.trash_types import UserSourceTrashableItemType

USER_SOURCE_ACTION_CONTEXT = _(
    'in application "%(application_name)s" (%(application_id)s).'
)


def _map_auth_provider_secrets(values: Dict[str, Any], map_secret) -> Dict[str, Any]:
    """
    Applies `map_secret` to the values of the encrypted fields of the auth providers
    in the undo/redo values of a user source, e.g. an OpenID Connect client secret.
    """

    if not values.get("auth_providers"):
        return values

    auth_providers = []
    for auth_provider in values["auth_providers"]:
        auth_provider = dict(auth_provider)
        model_class = app_auth_provider_type_registry.get(
            auth_provider["type"]
        ).model_class
        for field in model_class._meta.concrete_fields:
            if isinstance(field, EncryptedTextField) and auth_provider.get(field.name):
                auth_provider[field.name] = map_secret(auth_provider[field.name])
        auth_providers.append(auth_provider)
    return {**values, "auth_providers": auth_providers}


def encrypt_auth_provider_secrets(values: Dict[str, Any]) -> Dict[str, Any]:
    """
    The undo/redo values are stored in `core.Action`, so the auth provider secrets
    are encrypted like in their own table.
    """

    if not is_encryption_enabled():
        return values
    handler = EncryptionHandler()
    return _map_auth_provider_secrets(values, lambda value: handler.encrypt(str(value)))


def decrypt_auth_provider_secrets(values: Dict[str, Any]) -> Dict[str, Any]:
    return _map_auth_provider_secrets(values, EncryptionHandler().decrypt)


class CreateUserSourceActionType(UndoableActionType):
    type = "create_user_source"
    description = ActionTypeDescription(
        _("Create user source"),
        _("User source (%(user_source_id)s) created"),
        USER_SOURCE_ACTION_CONTEXT,
    )

    @dataclass
    class Params:
        application_id: int
        application_name: str
        user_source_id: int
        user_source_type: str

    @classmethod
    def do(
        cls,
        user: AbstractUser,
        user_source_type: UserSourceType,
        application: Application,
        before: Optional[UserSource] = None,
        **kwargs,
    ) -> UserSource:
        user_source = UserSourceService().create_user_source(
            user, user_source_type, application, before=before, **kwargs
        )

        cls.register_action(
            user=user,
            params=cls.Params(
                application.id,
                application.name,
                user_source.id,
                user_source_type.type,
            ),
            scope=cls.scope(application.id),
            workspace=application.workspace,
        )
        return user_source

    @classmethod
    def scope(cls, application_id: int):
        return ApplicationActionScopeType.value(application_id)

    @classmethod
    def undo(cls, user: AbstractUser, params: Params, action_to_undo: Action):
        user_source = UserSourceHandler().get_user_source_for_update(
            params.user_source_id
        )
        UserSourceService().delete_user_source(user, user_source)

    @classmethod
    def redo(cls, user: AbstractUser, params: Params, action_to_redo: Action):
        TrashHandler.restore_item(
            user,
            UserSourceTrashableItemType.type,
            params.user_source_id,
        )


class UpdateUserSourceActionType(UndoableActionType):
    type = "update_user_source"
    description = ActionTypeDescription(
        _("Update user source"),
        _("User source (%(user_source_id)s) updated"),
        USER_SOURCE_ACTION_CONTEXT,
    )

    @dataclass
    class Params:
        application_id: int
        application_name: str
        user_source_id: int
        user_source_original_params: Dict[str, Any]
        user_source_new_params: Dict[str, Any]

    @classmethod
    def do(
        cls,
        user: AbstractUser,
        user_source: UserSource,
        **kwargs,
    ) -> UserSource:
        updated = UserSourceService().update_user_source(user, user_source, **kwargs)

        application = updated.user_source.application
        cls.register_action(
            user=user,
            params=cls.Params(
                application.id,
                application.name,
                updated.user_source.id,
                encrypt_auth_provider_secrets(updated.original_values),
                encrypt_auth_provider_secrets(updated.new_values),
            ),
            scope=cls.scope(application.id),
            workspace=application.workspace,
        )
        return updated.user_source

    @classmethod
    def scope(cls, application_id: int):
        return ApplicationActionScopeType.value(application_id)

    @classmethod
    def undo(cls, user: AbstractUser, params: Params, action_to_undo: Action):
        user_source = UserSourceHandler().get_user_source_for_update(
            params.user_source_id
        )
        UserSourceService().update_user_source(
            user,
            user_source,
            **decrypt_auth_provider_secrets(params.user_source_original_params),
        )

    @classmethod
    def redo(cls, user: AbstractUser, params: Params, action_to_redo: Action):
        user_source = UserSourceHandler().get_user_source_for_update(
            params.user_source_id
        )
        UserSourceService().update_user_source(
            user,
            user_source,
            **decrypt_auth_provider_secrets(params.user_source_new_params),
        )


class DeleteUserSourceActionType(UndoableActionType):
    type = "delete_user_source"
    description = ActionTypeDescription(
        _("Delete user source"),
        _("User source (%(user_source_id)s) deleted"),
        USER_SOURCE_ACTION_CONTEXT,
    )

    @dataclass
    class Params:
        application_id: int
        application_name: str
        user_source_id: int

    @classmethod
    def do(cls, user: AbstractUser, user_source: UserSource) -> None:
        application = user_source.application
        # Captured before the user source is trashed.
        params = cls.Params(
            application.id,
            application.name,
            user_source.id,
        )

        UserSourceService().delete_user_source(user, user_source)

        cls.register_action(
            user=user,
            params=params,
            scope=cls.scope(application.id),
            workspace=application.workspace,
        )

    @classmethod
    def scope(cls, application_id: int):
        return ApplicationActionScopeType.value(application_id)

    @classmethod
    def undo(cls, user: AbstractUser, params: Params, action_to_undo: Action):
        TrashHandler.restore_item(
            user,
            UserSourceTrashableItemType.type,
            params.user_source_id,
        )

    @classmethod
    def redo(cls, user: AbstractUser, params: Params, action_to_redo: Action):
        user_source = UserSourceHandler().get_user_source_for_update(
            params.user_source_id
        )
        UserSourceService().delete_user_source(user, user_source)


class MoveUserSourceActionType(UndoableActionType):
    type = "move_user_source"
    description = ActionTypeDescription(
        _("Move user source"),
        _("User source (%(user_source_id)s) moved"),
        USER_SOURCE_ACTION_CONTEXT,
    )

    @dataclass
    class Params:
        application_id: int
        application_name: str
        user_source_id: int
        original_before_id: Optional[int]
        new_before_id: Optional[int]

    @classmethod
    def _ordered_sibling_ids(cls, user_source: UserSource) -> List[int]:
        return list(
            UserSource.objects.filter(application_id=user_source.application_id)
            .order_by("order", "id")
            .values_list("id", flat=True)
        )

    @classmethod
    def do(
        cls,
        user: AbstractUser,
        user_source: UserSource,
        before: Optional[UserSource] = None,
    ) -> UserSource:
        application = user_source.application

        # Capture the sibling that originally came right after the user source so the
        # move can be undone by placing it back before that sibling.
        sibling_ids = cls._ordered_sibling_ids(user_source)
        index = sibling_ids.index(user_source.id)
        original_before_id = (
            sibling_ids[index + 1] if index + 1 < len(sibling_ids) else None
        )

        moved_user_source = UserSourceService().move_user_source(
            user, user_source, before
        )

        cls.register_action(
            user=user,
            params=cls.Params(
                application.id,
                application.name,
                user_source.id,
                original_before_id,
                before.id if before else None,
            ),
            scope=cls.scope(application.id),
            workspace=application.workspace,
        )
        return moved_user_source

    @classmethod
    def scope(cls, application_id: int):
        return ApplicationActionScopeType.value(application_id)

    @classmethod
    def _move(cls, user: AbstractUser, user_source_id: int, before_id: Optional[int]):
        user_source = UserSourceHandler().get_user_source_for_update(user_source_id)
        before = UserSourceHandler().get_user_source(before_id) if before_id else None
        UserSourceService().move_user_source(user, user_source, before)

    @classmethod
    def undo(cls, user: AbstractUser, params: Params, action_to_undo: Action):
        cls._move(user, params.user_source_id, params.original_before_id)

    @classmethod
    def redo(cls, user: AbstractUser, params: Params, action_to_redo: Action):
        cls._move(user, params.user_source_id, params.new_before_id)
