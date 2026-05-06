#!/usr/bin/env python
from __future__ import absolute_import, unicode_literals

import argparse
import configparser
import os
import re
import sys

from ansible.parsing.vault import VaultLib, AnsibleVaultError

from encryptor import (
    ExplicitVaultSecret,
    get_files_in_paths,
    get_variable_lines,
    load_config,
)


VAULT_BLOCK_RE = re.compile(r'^(?P<name>\w+): !vault \|')


def _read_legacy_vault_path(prefix):
    cfg_path = os.path.join(prefix, 'ansible.cfg')
    if not os.path.exists(cfg_path):
        return None

    parser = configparser.ConfigParser()
    parser.read(cfg_path)
    if not parser.has_option('defaults', 'vault_password_file'):
        return None

    return os.path.expanduser(parser.get('defaults', 'vault_password_file'))


def _build_decrypt_pool(prefix, vault_groups, extra_vault_paths):
    """Aggregate every available vault password as a decryption secret.

    Order of registration: explicit --from-vault paths first (they're the user's
    declared source for this run), then ansible.cfg's legacy vault, then every v2
    group's file that exists locally. Deduplicated by absolute path so the same
    file isn't registered twice when --from-vault overlaps an existing source.
    """
    seen_paths = set()
    secrets = []

    for raw_path in extra_vault_paths or []:
        vault_path = os.path.expanduser(raw_path)
        if not os.path.exists(vault_path):
            sys.exit("encryptor_rotate: --from-vault path not found: {}".format(vault_path))
        if vault_path in seen_paths:
            continue
        seen_paths.add(vault_path)
        secrets.append(['from-vault', ExplicitVaultSecret(vault_path)])

    legacy_path = _read_legacy_vault_path(prefix)
    if legacy_path and os.path.exists(legacy_path) and legacy_path not in seen_paths:
        seen_paths.add(legacy_path)
        secrets.append(['default', ExplicitVaultSecret(legacy_path)])

    for group in vault_groups:
        vault_path = os.path.expanduser(group['vault_password_file'])
        if vault_path in seen_paths or not os.path.exists(vault_path):
            continue
        seen_paths.add(vault_path)
        secrets.append([group['vault_id'], ExplicitVaultSecret(vault_path)])

    return secrets


def _block_vault_id(encrypted_data):
    """Return the vault-id label embedded in a vault blob, or None for legacy 1.1."""
    header = encrypted_data.split('\n', 1)[0]
    parts = header.split(';')
    return parts[3] if len(parts) >= 4 else None


def _rotate_file(file_path, decrypt_vault, encrypt_vault, target_vault_id):
    with open(file_path, 'r') as stream:
        lines = stream.readlines()

    rotated = 0
    skipped = 0
    failed = 0

    i = 0
    while i < len(lines):
        match = VAULT_BLOCK_RE.match(lines[i])
        if not match:
            i += 1
            continue

        variable_name = match.group('name')
        block_lines = get_variable_lines(lines, i)
        encrypted_data = '\n'.join(l.strip() for l in block_lines[1:])

        if _block_vault_id(encrypted_data) == target_vault_id:
            skipped += 1
            i += len(block_lines)
            continue

        try:
            plaintext = decrypt_vault.decrypt(encrypted_data)
        except AnsibleVaultError as exc:
            sys.stderr.write(
                "encryptor_rotate: cannot decrypt {} in {}: {}\n".format(
                    variable_name, file_path, exc
                )
            )
            failed += 1
            i += len(block_lines)
            continue

        reencrypted = encrypt_vault.encrypt(plaintext, vault_id=target_vault_id)

        for _ in range(len(block_lines)):
            lines.pop(i)
        lines.insert(i, '{}: !vault |\n'.format(variable_name))
        new_lines = reencrypted.splitlines(True)
        for j, encrypted_line in enumerate(new_lines):
            lines.insert(i + j + 1, ' ' * 6 + encrypted_line.decode())

        rotated += 1
        i += 1 + len(new_lines)

    if rotated:
        with open(file_path, 'w') as stream:
            stream.writelines(lines)

    return rotated, skipped, failed


def main(prefix, extra_vault_paths=None):
    config = load_config(prefix)
    vault_groups = config.get('vault_groups')
    assert vault_groups, 'encryptor_rotate: vault_groups not configured -- rotate only applies to v2 mode'

    decrypt_secrets = _build_decrypt_pool(prefix, vault_groups, extra_vault_paths)
    if not decrypt_secrets:
        sys.exit('encryptor_rotate: no vault password files available; nothing can be decrypted')

    decrypt_vault = VaultLib(secrets=decrypt_secrets)

    total_failed = 0
    for group in vault_groups:
        vault_id = group['vault_id']
        target_path = os.path.expanduser(group['vault_password_file'])
        paths = group.get('paths') or []

        if not os.path.exists(target_path):
            sys.stderr.write(
                "encryptor_rotate: target vault file for group '{}' not found at {} -- "
                "skipping (create it first to rotate {} secrets)\n".format(vault_id, target_path, vault_id)
            )
            continue

        encrypt_vault = VaultLib(secrets=[[vault_id, ExplicitVaultSecret(target_path)]])

        print("encryptor_rotate: group '{}' -> {} over {}".format(vault_id, target_path, paths))
        for var_file in get_files_in_paths(prefix, paths):
            rotated, skipped, failed = _rotate_file(var_file, decrypt_vault, encrypt_vault, vault_id)
            total_failed += failed
            if rotated or failed:
                print("  {}: rotated={} skipped={} failed={}".format(var_file, rotated, skipped, failed))

    if total_failed:
        sys.exit('encryptor_rotate: {} block(s) could not be decrypted -- check that you have the source vault password file'.format(total_failed))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Re-encrypt every !vault block under its current vault_groups owner.')
    parser.add_argument('ansible_root', nargs='?', default='../ansible')
    parser.add_argument(
        '--from-vault', dest='from_vault', action='append', default=[],
        help='Extra vault password file(s) to use for decryption. Repeatable.',
    )
    args = parser.parse_args()

    main(args.ansible_root, args.from_vault)
