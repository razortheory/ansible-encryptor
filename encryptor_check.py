#!/usr/bin/env python
from __future__ import absolute_import, unicode_literals

import os
import re
import sys
from collections import defaultdict

from encryptor import (
    get_files_in_paths,
    get_variables_files,
    load_config,
)


def _check_config(vault_groups):
    """Validate group declarations: ids/paths must be unique and well-formed."""
    errors = []

    seen_ids = defaultdict(int)
    seen_paths = defaultdict(int)
    for group in vault_groups:
        vault_id = group.get('vault_id')
        if not vault_id:
            errors.append("group missing vault_id: {}".format(group))
            continue
        seen_ids[vault_id] += 1

        vault_path_raw = group.get('vault_password_file')
        if not vault_path_raw:
            errors.append("group '{}' missing vault_password_file".format(vault_id))
        else:
            seen_paths[os.path.expanduser(vault_path_raw)] += 1

        if not group.get('paths'):
            errors.append("group '{}' has empty paths -- nothing to encrypt".format(vault_id))

    for vault_id, count in seen_ids.items():
        if count > 1:
            errors.append("duplicate vault_id '{}' across {} groups".format(vault_id, count))
    for path, count in seen_paths.items():
        if count > 1:
            errors.append("duplicate vault_password_file '{}' across {} groups".format(path, count))

    return errors


def _expand_group_files(prefix, vault_groups):
    """Return {group_vault_id: set(file_paths)} for files actually present on disk."""
    return {
        group['vault_id']: set(get_files_in_paths(prefix, group.get('paths') or []))
        for group in vault_groups
    }


def _find_overlaps(group_files):
    """A file claimed by two groups can't be unambiguously encrypted -- flag it."""
    file_to_groups = defaultdict(list)
    for vault_id, files in group_files.items():
        for f in files:
            file_to_groups[f].append(vault_id)

    return {f: ids for f, ids in file_to_groups.items() if len(ids) > 1}


def _scan_uncovered(prefix, encrypted_variables, covered_files):
    """Look for stray plaintext secrets and !vault blocks outside any group's paths."""
    plaintext_re = re.compile(r'^(?P<name>{}): (?P<data>.*)'.format('|'.join(encrypted_variables)))

    plaintext_hits = defaultdict(list)
    vault_hits = defaultdict(list)

    for var_file in get_variables_files(prefix):
        if var_file in covered_files:
            continue

        with open(var_file, 'r') as stream:
            for line in stream:
                match = plaintext_re.match(line)
                if not match:
                    continue
                if '!vault' in match.group('data'):
                    vault_hits[var_file].append(match.group('name'))
                else:
                    plaintext_hits[var_file].append(match.group('name'))

    return plaintext_hits, vault_hits


def main(prefix):
    config = load_config(prefix)

    vault_groups = config.get('vault_groups')
    if not vault_groups:
        print('encryptor_check: v1 mode (no vault_groups) -- nothing to check')
        return

    encrypted_variables = config.get('encrypted_variables') or []
    if not encrypted_variables:
        sys.exit('encryptor_check: encrypted_variables is empty -- coverage check needs the secret list')

    errors = _check_config(vault_groups)

    group_files = _expand_group_files(prefix, vault_groups)
    overlaps = _find_overlaps(group_files)
    for f, ids in sorted(overlaps.items()):
        errors.append("file '{}' claimed by groups {} -- paths must not overlap".format(f, ids))

    covered = set()
    for files in group_files.values():
        covered.update(files)

    plaintext_hits, vault_hits = _scan_uncovered(prefix, encrypted_variables, covered)

    for f, names in sorted(plaintext_hits.items()):
        errors.append(
            "uncovered plaintext secret(s) {} in {} -- file is not in any vault_groups paths".format(
                names, f
            )
        )

    warnings = []
    for f, names in sorted(vault_hits.items()):
        warnings.append(
            "uncovered !vault block(s) {} in {} -- rekey will not visit this file".format(names, f)
        )

    for w in warnings:
        sys.stderr.write('encryptor_check: warning: {}\n'.format(w))

    if errors:
        for e in errors:
            sys.stderr.write('encryptor_check: error: {}\n'.format(e))
        sys.exit(1)

    print('encryptor_check: ok ({} group(s), {} covered file(s))'.format(
        len(vault_groups), len(covered)
    ))


if __name__ == '__main__':
    if len(sys.argv) == 1:
        prefix_dir = '../ansible'
    else:
        prefix_dir = sys.argv[1]

    main(prefix_dir)
