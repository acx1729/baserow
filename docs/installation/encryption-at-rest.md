# Encryption at rest

Baserow encrypts the secrets it stores in its database, like API tokens, integration
credentials and two-factor authentication secrets. A leaked database dump, backup or
replica, or someone reading the database with stolen credentials, only gets
ciphertext. The keys that protect it are never stored in the database: they're held by
a key provider, which is either a key passed to Baserow or a key in
[HashiCorp Vault](https://www.vaultproject.io/).

## What is encrypted

| Area                   | Encrypted columns                                                                                                                     |
|------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| API access             | Database API token keys, MCP endpoint keys. A SHA-256 hash is stored next to them to authenticate requests without decrypting.       |
| Two-factor auth        | TOTP secrets, and the provisioning URL and QR code while 2FA is being set up.                                                        |
| Integrations           | Slack bot tokens, SMTP passwords, AI integration settings and workspace generative AI settings (API keys).                          |
| Data syncs             | PostgreSQL passwords, Jira, GitHub, GitLab and HubSpot tokens, Airtable import session cookies.                                      |
| SSO                    | OAuth2 and OpenID Connect client secrets, for the instance and for application builder user sources.                                 |
| Webhooks               | Webhook URLs, header values, and the call log (URL, request, response and error).                                                   |
| Audit log (enterprise) | The parameters of every audit log entry, which can contain secrets like webhook URLs or MCP endpoint keys.                           |
| Import/export          | The private key used to sign exports.                                                                                                 |

A test in the backend fails when a column with a name like `password`, `secret`,
`token` or `api_key` is added without being encrypted.

The content of the tables that users create in Baserow isn't encrypted by the
application, because Baserow filters, sorts and searches it in the database. Protect it
with encryption of the database storage and backups (for example encrypted volumes or
an encrypted managed database), and restrict who can access the database and restore
its backups. Files uploaded by users are stored outside of the database, protect them
with encryption of the storage bucket or volume.

Some secrets can also exist outside of these columns:

- Redis holds the URL and headers of webhook calls that are waiting to be sent, in the
  Celery queue and the webhook queue. Protect Redis with a password, TLS and encrypted
  storage, or disable its persistence.
- Formulas aren't encrypted. A secret that's typed into a formula, for example in the
  headers of an HTTP request action, is stored as it is, also in the undo history.
  Integration credentials and SSO client secrets are never stored in the undo history.

## What it doesn't protect against

Encryption at rest protects the secrets from anyone who can read the database, but
not from anyone who can use Baserow's keys or change what Baserow does:

- **Write access to the database.** Someone who can change the database can, for
  example, add themselves to a workspace or change a webhook URL, and let Baserow use
  the secrets for them. Only give Baserow's database credentials to Baserow, restrict
  the network access to the database, and use read-only credentials for reporting and
  backups.
- **Access to a running Baserow process or its configuration.** Baserow has to decrypt
  the secrets to use them, so someone who can run code in Baserow, or read its memory
  or environment variables, can decrypt them too. With HashiCorp Vault, revoking
  Baserow's Vault identity stops that, and every data key that's unwrapped is recorded
  in the Vault audit log.
- **Data outside of the encrypted columns**, see above.

## How it works

Baserow uses envelope encryption:

1. Every value is encrypted with AES-256-GCM using a random **data key**.
2. The data key is **wrapped** (encrypted) by a **key encryption key** that is held by
   the key provider. Only the wrapped data key is stored, next to the value.
3. To decrypt, Baserow asks the key provider to unwrap the data key once, and keeps it
   in memory.

An encrypted value is self-contained and looks like this:

```
bxenc:1:<key provider>:<wrapped data key>:<nonce + ciphertext + authentication tag>
```

The header is authenticated, so a value can't be modified or combined with another data
key without being detected. Every value is encrypted with a random nonce, so the same
secret is never stored twice in the same way.

Empty values aren't encrypted. Values that were stored before encryption at rest
existed keep working, and are encrypted by the `encrypt_data` management command, see
[Upgrading](#upgrading).

A secret is decrypted when it's used, not when its object is loaded. A value that can't
be decrypted, for example because its key was removed or the key provider is
unreachable, only makes the features that use it fail, and saving its object keeps the
stored value.

## Choosing a key provider

### Default: key derived from SECRET_KEY

Without any configuration, Baserow derives the key encryption key from `SECRET_KEY`.
This already protects against leaks of the database alone, because `SECRET_KEY` isn't
stored in the database. Anyone who has both the database and `SECRET_KEY` can decrypt
the secrets.

Changing `SECRET_KEY` makes the encrypted values unreadable. Configure a dedicated key
first and run `./baserow encrypt_data` before changing it.

### Dedicated local keys

Generate a key and pass it with `BASEROW_ENCRYPTION_KEYS`:

```bash
./baserow generate_encryption_key
# or: openssl rand -base64 32
```

```bash
BASEROW_ENCRYPTION_KEYS=<the generated key>
```

You can also put the keys in a file, for example a Docker or Kubernetes secret, or a
file rendered by the Vault Agent, and set `BASEROW_ENCRYPTION_KEYS_FILE` to its path.

The key must be the same for every Baserow backend and Celery process. Store it in a
secrets manager, not next to the database backups.

### HashiCorp Vault (recommended for production)

With the `hashicorp_vault` provider, the key encryption key is a key of the Vault
[Transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit).
It never leaves Vault: Baserow asks Vault to generate data keys and to unwrap them.
Stealing the database and the Baserow configuration isn't enough anymore, the attacker
also needs a valid Vault identity. Every unwrap is recorded in the Vault audit log, and
revoking Baserow's access to the Transit key makes the secrets unreadable.

[OpenBao](https://openbao.org), the open source fork of Vault, has the same Transit
secrets engine, API and auth methods. Use the same provider and set up OpenBao with the
commands below, using `bao` instead of `vault`.

1. Enable the Transit engine and create the key:

   ```bash
   vault secrets enable transit
   vault write -f transit/keys/baserow type=aes256-gcm96
   ```

2. Create a policy that only allows generating and unwrapping data keys:

   ```hcl
   # baserow-encryption.hcl
   path "transit/datakey/plaintext/baserow" {
     capabilities = ["update"]
   }
   path "transit/decrypt/baserow" {
     capabilities = ["update"]
   }
   ```

   ```bash
   vault policy write baserow-encryption baserow-encryption.hcl
   ```

3. Give Baserow a Vault identity with that policy, using one of these auth methods:

   - **AppRole**, for Docker and virtual machines:

     ```bash
     vault auth enable approle
     vault write auth/approle/role/baserow token_policies=baserow-encryption \
       token_ttl=1h token_max_ttl=4h
     vault read auth/approle/role/baserow/role-id
     vault write -f auth/approle/role/baserow/secret-id
     ```

     ```bash
     BASEROW_VAULT_AUTH_METHOD=approle
     BASEROW_VAULT_APPROLE_ROLE_ID=<role id>
     BASEROW_VAULT_APPROLE_SECRET_ID=<secret id>
     ```

   - **Kubernetes**, using the service account of the Baserow pods:

     ```bash
     vault auth enable kubernetes
     vault write auth/kubernetes/role/baserow \
       bound_service_account_names=baserow \
       bound_service_account_namespaces=baserow \
       token_policies=baserow-encryption token_ttl=1h
     ```

     ```bash
     BASEROW_VAULT_AUTH_METHOD=kubernetes
     BASEROW_VAULT_KUBERNETES_ROLE=baserow
     ```

   - **Token**, for example a token written by the
     [Vault Agent](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent)
     auto-auth sink. The file is read again when Vault rejects the token, so tokens
     renewed by the agent are picked up automatically:

     ```bash
     BASEROW_VAULT_AUTH_METHOD=token
     BASEROW_VAULT_TOKEN_FILE=/vault/token
     ```

4. Configure every Baserow backend and Celery process:

   ```bash
   BASEROW_ENCRYPTION_PROVIDER=hashicorp_vault
   BASEROW_VAULT_ADDR=https://vault.example.com:8200
   # Optional:
   # BASEROW_VAULT_NAMESPACE=admin/baserow
   # BASEROW_VAULT_CACERT=/etc/ssl/vault-ca.pem
   # BASEROW_VAULT_TRANSIT_MOUNT=transit
   # BASEROW_VAULT_TRANSIT_KEY=baserow
   ```

5. Run `./baserow encrypt_data` to re-encrypt the existing secrets with Vault.

Values that were encrypted with a local key stay readable after switching to Vault, as
long as that key (or `SECRET_KEY`) is still configured. Run `./baserow encrypt_data`
before removing it.

Every process asks Vault for a new data key at most once a day, and unwraps each data
key it reads once. When Vault is unreachable, the processes keep using their current
data key to encrypt, and the data keys they already unwrapped to decrypt. A process
that starts while Vault is unreachable can't read or write secrets until Vault is back,
but everything else keeps working:

- A secret is only decrypted when a feature uses it. Loading, for example, a workspace
  with generative AI settings or an integration doesn't need Vault, only using the API
  key or the credentials does.
- Saving an object doesn't need Vault either when its secrets didn't change.
- API tokens and MCP endpoints are authenticated with the hash of their key, and the
  login page doesn't read the SSO client secrets.

All the environment variables are listed in the
[configuration reference](configuration.md#encryption-at-rest-configuration).

## Upgrading

New installations encrypt secrets from the start.

After upgrading an existing installation, secrets are still written in plain text, so
that the previous version, which keeps running during a rolling upgrade, can read
everything the new version writes. Once every instance runs the new version, run:

```bash
# Shows, per column, how many values are still stored in plain text.
./baserow encrypt_data --dry-run
# Enables encryption at rest and encrypts the existing secrets.
./baserow encrypt_data
```

The `baserow/baserow` all-in-one image runs it automatically on startup, because the
previous version never runs next to it. Set `BASEROW_ENCRYPT_DATA_ON_STARTUP=true` to do
the same with the other images, when the previous version can't run while the new one
starts, for example with a single backend and Celery container that are restarted
together.

The command first checks that the key provider works, for example that Vault is
reachable and that Baserow is allowed to use the Transit key, and changes nothing when
it doesn't. It's safe to run multiple times and while Baserow is running: a value that
changes while it's being encrypted is left alone, because it's already written
encrypted. Once encryption is enabled, the previous version can't read the secrets
anymore, so a downgrade requires restoring a backup from before it was enabled.

## Rotating keys

**Local keys.** Add the new key in front of the old one, so that the new key encrypts
and the old one can still decrypt, restart Baserow, re-encrypt, and remove the old key:

```bash
BASEROW_ENCRYPTION_KEYS=<new key>,<old key>
./baserow encrypt_data
BASEROW_ENCRYPTION_KEYS=<new key>
```

**HashiCorp Vault.** Rotate the Transit key in Vault. New data keys are wrapped with the
new version within a day, or immediately after a restart. Then re-encrypt, and
optionally stop Vault from decrypting the old versions:

```bash
vault write -f transit/keys/baserow/rotate
./baserow encrypt_data
vault write transit/keys/baserow/config min_decryption_version=<latest version>
```

Don't rename or recreate the Transit key: values encrypted with it can only be
decrypted with the same key.

## Verifying

`./baserow encrypt_data --dry-run` reports, per encrypted column, how many values are
stored and how many are still in plain text or protected by an old key. You can also
check the database directly, every non empty value must start with `bxenc:`:

```sql
SELECT count(*) FROM integrations_slackbotintegration
WHERE token <> '' AND token NOT LIKE 'bxenc:%';
```

## Backups and disaster recovery

- Back up the keys, or make sure the Vault Transit key is backed up, separately from the
  database backups. Without the key, the encrypted secrets can't be recovered: the
  integrations, data syncs, SSO providers, API tokens and webhooks have to be configured
  again.
- Keep every key that encrypted values in a backup you might restore, until that backup
  expires.
- Destroying a key, or revoking Baserow's access to the Transit key, makes every value
  encrypted with it unreadable.
