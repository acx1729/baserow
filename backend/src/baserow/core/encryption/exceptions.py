class EncryptionError(Exception):
    """Base class for every encryption at rest related error."""


class EncryptionConfigurationError(EncryptionError):
    """
    Raised when the encryption keys or the key provider are missing or invalid, for
    example when BASEROW_ENCRYPTION_KEYS contains a value that isn't a base64 encoded
    32 byte key.
    """


class DecryptionError(EncryptionError):
    """
    Raised when an encrypted value can't be decrypted. This typically means that the
    key that protects the value is not configured anymore, or that the value has
    been tampered with.
    """


class KeyProviderError(EncryptionError):
    """
    Raised when the key provider, for example HashiCorp Vault, fails to generate or
    unwrap a data key.
    """
