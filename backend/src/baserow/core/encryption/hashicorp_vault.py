import base64
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from django.conf import settings

import requests

from .exceptions import (
    DecryptionError,
    EncryptionConfigurationError,
    KeyProviderError,
)

VAULT_AUTH_METHOD_TOKEN = "token"  # nosec
VAULT_AUTH_METHOD_APPROLE = "approle"
VAULT_AUTH_METHOD_KUBERNETES = "kubernetes"
VAULT_AUTH_METHODS = (
    VAULT_AUTH_METHOD_TOKEN,
    VAULT_AUTH_METHOD_APPROLE,
    VAULT_AUTH_METHOD_KUBERNETES,
)

# Login tokens are renewed once this share of their lease duration has passed.
TOKEN_RENEWAL_LEASE_SHARE = 0.8


class HashiCorpVaultRequestError(KeyProviderError):
    """Raised when HashiCorp Vault responds with an error status code."""

    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


def get_vault_ciphertext_version(ciphertext: str) -> int:
    """
    Returns the version of the Transit key that produced a Vault ciphertext. Vault
    ciphertexts look like `vault:v3:base64data`.

    :param ciphertext: The ciphertext returned by Vault.
    :return: The key version or 0 if the ciphertext isn't recognized.
    """

    parts = ciphertext.split(":", 2)
    if len(parts) != 3 or parts[0] != "vault" or not parts[1].startswith("v"):
        return 0
    try:
        return int(parts[1][1:])
    except ValueError:
        return 0


def _read_secret_file(path: str) -> str:
    try:
        return Path(path).read_text().strip()
    except OSError as exc:
        raise EncryptionConfigurationError(
            f"Could not read the HashiCorp Vault credentials file {path}: "
            f"{exc.strerror}."
        ) from exc


class HashiCorpVaultClient:
    """
    A minimal client for the parts of the HashiCorp Vault HTTP API that Baserow
    needs: logging in, and generating and decrypting data keys with the Transit
    secrets engine. The Transit key itself never leaves Vault.

    https://developer.hashicorp.com/vault/api-docs/secret/transit
    """

    def __init__(
        self,
        addr: str,
        transit_mount: str = "transit",
        transit_key: str = "baserow",
        namespace: str = "",
        cacert: str = "",
        timeout: float = 10,
        auth_method: str = VAULT_AUTH_METHOD_TOKEN,
        auth_mount: str = "",
        token: str = "",
        token_file: str = "",
        approle_role_id: str = "",
        approle_secret_id: str = "",
        kubernetes_role: str = "",
        kubernetes_token_path: str = "",
    ):
        if not addr.startswith(("http://", "https://")):
            raise EncryptionConfigurationError(
                "BASEROW_VAULT_ADDR must be an http:// or https:// URL."
            )
        if auth_method not in VAULT_AUTH_METHODS:
            raise EncryptionConfigurationError(
                f"BASEROW_VAULT_AUTH_METHOD must be one of "
                f"{', '.join(VAULT_AUTH_METHODS)}, got '{auth_method}'."
            )

        self.addr = addr.rstrip("/")
        self.transit_mount = transit_mount.strip("/")
        self.transit_key = transit_key
        self.namespace = namespace
        self.verify = cacert or True
        self.timeout = timeout
        self.auth_method = auth_method
        self.auth_mount = (auth_mount or auth_method).strip("/")
        self.token = token
        self.token_file = token_file
        self.approle_role_id = approle_role_id
        self.approle_secret_id = approle_secret_id
        self.kubernetes_role = kubernetes_role
        self.kubernetes_token_path = kubernetes_token_path

        self._lock = threading.Lock()
        self._client_token: Optional[str] = None
        self._client_token_renew_at: Optional[float] = None

    @classmethod
    def from_settings(cls) -> "HashiCorpVaultClient":
        return cls(
            addr=settings.BASEROW_VAULT_ADDR,
            transit_mount=settings.BASEROW_VAULT_TRANSIT_MOUNT,
            transit_key=settings.BASEROW_VAULT_TRANSIT_KEY,
            namespace=settings.BASEROW_VAULT_NAMESPACE,
            cacert=settings.BASEROW_VAULT_CACERT,
            timeout=settings.BASEROW_VAULT_TIMEOUT,
            auth_method=settings.BASEROW_VAULT_AUTH_METHOD,
            auth_mount=settings.BASEROW_VAULT_AUTH_MOUNT,
            token=settings.BASEROW_VAULT_TOKEN,
            token_file=settings.BASEROW_VAULT_TOKEN_FILE,
            approle_role_id=settings.BASEROW_VAULT_APPROLE_ROLE_ID,
            approle_secret_id=settings.BASEROW_VAULT_APPROLE_SECRET_ID,
            kubernetes_role=settings.BASEROW_VAULT_KUBERNETES_ROLE,
            kubernetes_token_path=settings.BASEROW_VAULT_KUBERNETES_TOKEN_PATH,
        )

    def generate_data_key(self) -> Tuple[bytes, str]:
        """
        Asks Vault for a new 256 bit data key.

        :return: The plaintext data key and the same key wrapped by the Transit key.
        """

        response = self._request(
            "POST",
            f"{self.transit_mount}/datakey/plaintext/{self.transit_key}",
            {"bits": 256},
        )
        data = response["data"]
        return base64.b64decode(data["plaintext"]), data["ciphertext"]

    def decrypt(self, ciphertext: str) -> bytes:
        """
        Unwraps a data key that was previously generated by `generate_data_key`.

        :param ciphertext: The wrapped data key.
        :raises DecryptionError: When Vault refuses to decrypt the ciphertext, for
            example because its key version is below `min_decryption_version`.
        :return: The plaintext data key.
        """

        try:
            response = self._request(
                "POST",
                f"{self.transit_mount}/decrypt/{self.transit_key}",
                {"ciphertext": ciphertext},
            )
        except HashiCorpVaultRequestError as exc:
            if exc.status_code == 400:
                raise DecryptionError(str(exc)) from exc
            raise
        return base64.b64decode(response["data"]["plaintext"])

    def _get_client_token(self) -> str:
        with self._lock:
            if self._client_token is not None and (
                self._client_token_renew_at is None
                or time.monotonic() < self._client_token_renew_at
            ):
                return self._client_token

            token, lease_duration = self._login()
            self._client_token = token
            self._client_token_renew_at = (
                time.monotonic() + lease_duration * TOKEN_RENEWAL_LEASE_SHARE
                if lease_duration
                else None
            )
            return token

    def _forget_client_token(self):
        with self._lock:
            self._client_token = None
            self._client_token_renew_at = None

    def _login(self) -> Tuple[str, Optional[int]]:
        """
        Returns a Vault token and its lease duration in seconds, None if the token
        doesn't expire or is managed outside of Baserow.
        """

        if self.auth_method == VAULT_AUTH_METHOD_TOKEN:
            # A token file is read again after every authentication failure, so a
            # token renewed by the Vault Agent is picked up automatically.
            token = self.token or (
                _read_secret_file(self.token_file) if self.token_file else ""
            )
            if not token:
                raise EncryptionConfigurationError(
                    "BASEROW_VAULT_TOKEN or BASEROW_VAULT_TOKEN_FILE must be set "
                    "when BASEROW_VAULT_AUTH_METHOD is 'token'."
                )
            return token, None

        if self.auth_method == VAULT_AUTH_METHOD_APPROLE:
            if not self.approle_role_id or not self.approle_secret_id:
                raise EncryptionConfigurationError(
                    "BASEROW_VAULT_APPROLE_ROLE_ID and BASEROW_VAULT_APPROLE_SECRET_ID "
                    "must be set when BASEROW_VAULT_AUTH_METHOD is 'approle'."
                )
            payload = {
                "role_id": self.approle_role_id,
                "secret_id": self.approle_secret_id,
            }
        else:
            if not self.kubernetes_role:
                raise EncryptionConfigurationError(
                    "BASEROW_VAULT_KUBERNETES_ROLE must be set when "
                    "BASEROW_VAULT_AUTH_METHOD is 'kubernetes'."
                )
            payload = {
                "role": self.kubernetes_role,
                "jwt": _read_secret_file(self.kubernetes_token_path),
            }

        response = self._request(
            "POST", f"auth/{self.auth_mount}/login", payload, authenticated=False
        )
        auth = response["auth"]
        return auth["client_token"], auth.get("lease_duration") or None

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        authenticated: bool = True,
        retry_authentication: bool = True,
    ) -> Dict[str, Any]:
        headers = {}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        if authenticated:
            headers["X-Vault-Token"] = self._get_client_token()

        try:
            response = requests.request(
                method,
                f"{self.addr}/v1/{path}",
                json=payload,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify,
            )
        except requests.RequestException as exc:
            raise KeyProviderError(
                f"Could not connect to HashiCorp Vault at {self.addr}: {exc}"
            ) from exc

        if response.status_code == 403 and authenticated and retry_authentication:
            # The token could have expired or been revoked. Log in again once.
            self._forget_client_token()
            return self._request(
                method, path, payload, authenticated, retry_authentication=False
            )

        if not response.ok:
            try:
                errors = response.json().get("errors") or []
            except ValueError:
                errors = []
            details = "; ".join(str(error) for error in errors) or response.reason
            raise HashiCorpVaultRequestError(
                f"HashiCorp Vault responded with HTTP {response.status_code} to "
                f"{method} /v1/{path}: {details}",
                response.status_code,
            )

        return response.json() if response.content else {}
