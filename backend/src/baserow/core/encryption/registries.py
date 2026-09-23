from abc import ABC, abstractmethod
from typing import Tuple

from baserow.core.registry import Instance, Registry


class KeyProviderType(Instance, ABC):
    """
    A key provider protects the data encryption keys (DEKs) that Baserow uses to
    encrypt values at rest. It never sees the encrypted values themselves: it only
    generates new data keys and unwraps previously wrapped ones. This allows the key
    encryption key (KEK) to live outside of Baserow and its database, for example in
    HashiCorp Vault.

    The `type` of the provider is stored in every encrypted value, so it must never
    change once values have been encrypted with it.
    """

    def is_configured(self) -> bool:
        """
        Indicates whether the provider has all the settings it needs. A provider that
        isn't configured can't encrypt new values nor decrypt existing ones.
        """

        return True

    @abstractmethod
    def generate_data_key(self) -> Tuple[bytes, bytes]:
        """
        Generates a new random 256 bit data key.

        :return: A tuple containing the plaintext data key, which is only kept in
            memory, and the wrapped data key, which is stored next to the values that
            are encrypted with it.
        """

    @abstractmethod
    def unwrap_data_key(self, wrapped_key: bytes) -> bytes:
        """
        Unwraps a data key that was previously returned by `generate_data_key`.

        :param wrapped_key: The wrapped data key.
        :raises DecryptionError: When the key that wrapped the data key isn't
            available anymore.
        :raises KeyProviderError: When the provider can't be reached.
        :return: The plaintext data key.
        """

    def is_wrapped_with_current_key(
        self, wrapped_key: bytes, current_wrapped_key: bytes
    ) -> bool:
        """
        Indicates whether a wrapped data key is protected by the same key encryption
        key version as a freshly generated data key. This is used to find the values
        that must be re-encrypted after rotating the key encryption key.

        :param wrapped_key: The wrapped data key of an existing value.
        :param current_wrapped_key: The wrapped data key that is currently used to
            encrypt new values.
        """

        return True

    def reset(self):
        """
        Forgets any state the provider cached, like parsed keys or authentication
        tokens. Called when the related settings change.
        """


class KeyProviderTypeRegistry(Registry[KeyProviderType]):
    """
    Contains all the key providers that can protect the data encryption keys. The
    provider used to encrypt new values is selected with the
    BASEROW_ENCRYPTION_PROVIDER setting, all the configured providers can decrypt.
    """

    name = "encryption_key_provider"


key_provider_type_registry: KeyProviderTypeRegistry = KeyProviderTypeRegistry()
