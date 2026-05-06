#!/usr/bin/env python
from __future__ import absolute_import, unicode_literals

import os
import re
import sys

from ansible.parsing.vault import VaultLib

from encryptor import load_config, get_variable_lines, VaultSecret, ExplicitVaultSecret


def _build_secrets(prefix, config):
    """Aggregate all available vault secrets so VaultLib can decrypt blobs from any group.

    In vault_groups mode we register one secret per group whose vault file exists;
    VaultLib will try each in turn. Missing files are skipped (the user may not have
    access to all environments). In legacy mode we fall back to ansible.cfg's
    vault_password_file, preserving the original behavior for repos that haven't
    migrated to vault_groups.
    """
    vault_groups = config.get('vault_groups')
    if vault_groups:
        secrets = []
        for group in vault_groups:
            vault_path = os.path.expanduser(group['vault_password_file'])
            if os.path.exists(vault_path):
                secrets.append([group['vault_id'], ExplicitVaultSecret(vault_path)])
            else:
                sys.stderr.write(
                    "encryptor_view: vault file for group '{}' not found at {} -- skipping\n".format(
                        group['vault_id'], vault_path
                    )
                )
        if secrets:
            return secrets
        sys.stderr.write(
            "encryptor_view: no vault_groups files available; falling back to ansible.cfg vault_password_file\n"
        )
    return [['default', VaultSecret(prefix)]]


def main(prefix, file_path):
    # load list of protected variables
    config = load_config(prefix)

    encrypted_variables = config.get('encrypted_variables')
    assert encrypted_variables, 'No variables to encrypt'

    vault = VaultLib(secrets=_build_secrets(prefix, config))

    encrypted_variable_regexp = r'^(?P<name>\w+): !vault \|'

    with open(os.path.join(prefix, file_path), 'r') as encrypted_file:
        lines = encrypted_file.readlines()

        i = 0
        while i < len(lines):
            line = lines[i]

            match = re.match(encrypted_variable_regexp, line)
            if not match:
                i += 1
                continue

            variable_name = match.group(1)
            variable_lines = get_variable_lines(lines, i)
            encrypted_data = '\n'.join(map(lambda l: l.strip(), variable_lines[1:]))

            for j in range(len(variable_lines)):
                lines.pop(i)

            decrypted_data = vault.decrypt(encrypted_data).decode()
            lines.insert(i, '{}: {}\n'.format(variable_name, decrypted_data))

            i += 1

        for line in lines:
            sys.stdout.write(line)
        sys.stdout.write('\n')


if __name__ == '__main__':
    assert len(sys.argv) >= 3, 'Config or Path is not provided, please specify.'

    main(sys.argv[1], sys.argv[2])
