from django.contrib.auth import get_user_model
from django.db import models

from baserow.core.encryption.fields import EncryptedTextField
from baserow.core.encryption.mixins import LookupHashMixin
from baserow.core.mixins import (
    HierarchicalModelMixin,
    ParentWorkspaceTrashableModelMixin,
)
from baserow.core.models import Workspace

User = get_user_model()


class MCPEndpoint(
    LookupHashMixin,
    HierarchicalModelMixin,
    ParentWorkspaceTrashableModelMixin,
    models.Model,
):
    """
    An MCP endpoint can be used to authenticate and access the Baserow MCP server.
    It provides API access to the Machine Comprehension Protocol.
    """

    name = models.CharField(
        max_length=100,
        help_text="The human readable name of the MCP endpoint for the user.",
    )
    # Encrypted at rest, use `key_hash` to find an endpoint by key.
    key = EncryptedTextField(
        max_length=32,
        help_text="The unique endpoint key that can be used to authorize for the MCP "
        "service.",
    )
    key_hash = models.CharField(
        max_length=64,
        unique=True,
        null=True,
        editable=False,
        help_text="The SHA-256 hash of the key, used to find an endpoint by key.",
    )
    created = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, help_text="The user that owns the MCP endpoint."
    )
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        help_text="The workspace that the MCP endpoint belongs to.",
    )

    lookup_hash_fields = {"key": "key_hash"}

    class Meta:
        ordering = ("id",)

    def get_parent(self):
        return self.workspace
