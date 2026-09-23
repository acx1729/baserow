from typing import Dict

from .handler import EncryptionHandler


class LookupHashMixin:
    """
    Keeps a hash of encrypted fields in sync on save, so that a row can be found by
    the value of an encrypted field, like an API token. `lookup_hash_fields` maps the
    name of an encrypted field to the name of the field that stores its hash. Use
    `baserow.core.encryption.utils.get_by_lookup_hash` to find a row.
    """

    lookup_hash_fields: Dict[str, str] = {}

    def refresh_lookup_hashes(self):
        deferred_fields = self.get_deferred_fields()
        for field_name, hash_field_name in self.lookup_hash_fields.items():
            if field_name in deferred_fields:
                continue
            value = getattr(self, field_name)
            setattr(
                self,
                hash_field_name,
                EncryptionHandler.hash_for_lookup(value) if value else None,
            )

    def save(self, *args, **kwargs):
        self.refresh_lookup_hashes()

        update_fields = kwargs.get("update_fields")
        if update_fields is not None:
            kwargs["update_fields"] = {
                *update_fields,
                *(
                    hash_field_name
                    for field_name, hash_field_name in self.lookup_hash_fields.items()
                    if field_name in update_fields
                ),
            }
        super().save(*args, **kwargs)
