# ansible-encryptor

In-place vault encryption / decryption for variables in Ansible inventory and playbook YAML files.

Reads a list of "secret variable names" from `encryptor.yml`, walks variable directories (`group_vars/`, `host_vars/`, `inventories/`, `playbooks/`, etc.), finds plaintext values for those variables, and rewrites them as `!vault | …` blocks encrypted with Ansible's vault format. The matching `encryptor_view.py` decrypts a single file back to plaintext for inspection.

The point: keep secrets *next to* the rest of the variable definitions instead of in a separate per-secret vault file, while still using Ansible's standard vault on disk. `ansible-playbook` reads the resulting `!vault` blocks natively — the encryptor is purely a developer-side authoring tool.

## Requirements

- Python 3
- `ansible` installed (uses `ansible.parsing.vault.VaultLib`)
- `pyyaml`

`requirements.txt` covers these.

## Configuration — `encryptor.yml`

The config lives at `<ansible_root>/encryptor.yml`. It must declare which variables to encrypt; it may also (v2 schema, see below) declare per-environment vault groups.

### v1 schema — single vault for the whole repo

```yaml
encrypted_variables:
  - SECRET_KEY
  - DATABASE_URL
  - NEWRELIC_LICENCE_KEY
  - SENTRY_DSN
```

In v1 mode the encryptor walks **all** variable folders under `<ansible_root>/` (`env_vars/`, `group_vars/`, `host_vars/`, `inventories/`, `playbooks/`, `roles/common/vars/`, `roles/ansible-variables/vars/`) and encrypts every plaintext occurrence of a listed variable using the single vault file pointed to by `vault_password_file` in `<ansible_root>/ansible.cfg`. Output blocks are produced in legacy format `$ANSIBLE_VAULT;1.1;AES256` (no vault-id label). This matches the original behavior of the script and is what every existing repo using this submodule sees.

### v2 schema — per-environment vault groups

When secrets for different environments need different vault keys (e.g. testnet developers should not have prod-vault access), declare `vault_groups` in `encryptor.yml`:

```yaml
vault_groups:
  - vault_id: prod
    vault_password_file: ~/.ansible/myproject-prod.vault
    paths:
      - playbooks/prod
      - inventories/host_vars/prod-server.yml

  - vault_id: testnet
    vault_password_file: ~/.ansible/myproject-testnet.vault
    paths:
      - playbooks/testnet
      - inventories/host_vars/testnet-server.yml

encrypted_variables:
  - SECRET_KEY
  - DATABASE_URL
  - DISTRIBUTOR_SIGNER
```

Behavior in v2 mode:
- Each group is processed independently. The encryptor walks **only** the paths listed for that group and encrypts with **that group's** vault password file. The resulting `!vault` blocks carry an explicit vault-id label (`$ANSIBLE_VAULT;1.2;AES256;<vault_id>`).
- A group whose `vault_password_file` does not exist on disk is skipped with a warning. This is the access-control mechanism: a developer who only has `~/.ansible/myproject-testnet.vault` runs the encryptor and modifies only testnet secrets; prod secrets are not touched.
- Files outside every declared `paths` set are not visited. This is intentional — shared `inventories/group_vars/all/` files typically don't contain secrets and stay untouched.
- The decryptor (`encryptor_view.py`) aggregates **all available** vault files into a single `VaultLib`, so it can read blobs whose vault-id is present locally; missing vault files are skipped with a warning, and blocks they would have decrypted will fail with the standard Ansible error.

The two schemas are mutually exclusive in a given config: if `vault_groups` is set, the encryptor uses v2 mode; if it's absent, v1 mode (legacy behavior). All other repos using the submodule continue to work unchanged.

## Usage

Run from the repo that hosts both `<ansible_root>/encryptor.yml` and the submodule:

```bash
# Encrypt: rewrite plaintext occurrences of every listed variable as !vault blocks.
# Idempotent — already-encrypted blocks are skipped with a "skipping" message.
python encryptor/encryptor.py ansible

# Decrypt a single file to stdout (does not modify the file on disk).
python encryptor/encryptor_view.py ansible playbooks/testnet/group_vars/all/django_variables.yml
```

Both scripts take the ansible root path as the first argument.

## Adding a new secret variable

1. Add the variable name to `encrypted_variables` in `encryptor.yml`.
2. Edit the YAML file where the secret should live. Write it as a plain key/value:
   `SOME_KEY: my-secret-value`.
3. Run `python encryptor/encryptor.py ansible`. The script will replace the plain value with a `!vault | …` block in place.
4. Commit the resulting file.

## Vault file lookup

- **v1 mode:** the script reads `[defaults] vault_password_file` from `<ansible_root>/ansible.cfg`. If that file exists, its contents are the password. If it does not exist, the script prompts on stdin and *writes the entered password to that path* — so the next run is non-interactive. (Inherited behavior; unchanged.)
- **v2 mode:** each group's `vault_password_file` is treated as an absolute or `~`-relative path. The script reads it directly; if missing, the group is skipped (no prompt).

## Migration helpers

Three companion scripts assist the v1 → v2 migration:

```bash
# Print a v2 vault_groups stub derived from playbooks/<env>/ subdirs and matching host_vars.
python encryptor/encryptor_init.py ansible

# Verify v2 coverage: duplicate vault_ids/files, overlapping paths, YAML files outside any
# vault_groups paths that still contain plaintext (error) or !vault (warning) secrets.
python encryptor/encryptor_check.py ansible

# Rotate every !vault block in each group's paths under that group's current vault_id.
# Decrypts using any available vault password (ansible.cfg legacy + every group's file),
# re-encrypts under the group's vault. Idempotent: blocks already labeled with the
# group's vault_id are skipped.
python encryptor/encryptor_rotate.py ansible

# Pass an explicit source vault when rotating to a fresh password file. Repeatable.
# Use this when the previous vault file is not (or no longer) referenced from ansible.cfg
# or any vault_groups entry, e.g. when rotating <env>'s password to a new file.
python encryptor/encryptor_rotate.py ansible --from-vault ~/.ansible/<repo>-<env>-old.vault
```

Typical migration flow for an environment moving off the shared legacy vault:

1. Generate the new password file: `head -c 32 /dev/urandom | base64 > ~/.ansible/<repo>-<env>.vault`.
2. Edit `encryptor.yml`: point that group's `vault_password_file` at the new path.
3. Run `encryptor_rotate.py`. It decrypts the legacy blocks via `ansible.cfg`'s `vault_password_file`, re-encrypts them under the new group vault, and rewrites the YAML files in place.
4. Run `encryptor_check.py` to confirm coverage.
5. Once every environment has its own vault file, the legacy `vault_password_file` in `ansible.cfg` can be removed or repointed.

To rotate an already-v2 group's password to a fresh file (e.g. compromise response, key hygiene): generate the new file, point the group's `vault_password_file` at it, then run `encryptor_rotate.py --from-vault <path-to-old-file>`. Delete the old file once the rotation completes successfully.

## Limitations

- Variable detection is regex-based on line prefix `^<NAME>: `; values must be a single line (multi-line YAML scalars at the top of a key are not supported as input — but the resulting `!vault | …` block, which is multi-line, is correctly preserved on subsequent runs).
- `encryptor_rotate.py` requires v2 mode (`vault_groups` declared). For pure v1 repos, use `ansible-vault rekey` directly on the YAML files.
