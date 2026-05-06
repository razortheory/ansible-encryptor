#!/usr/bin/env python
from __future__ import absolute_import, unicode_literals

import argparse
import os
import re
import sys

import yaml

from encryptor import YAML_EXTENSIONS, get_variables_files


VAULT_BLOCK_RE = re.compile(r'^(?P<name>\w+): !vault \|')


def _detect_repo_prefix(ansible_root):
    """Default vault-file prefix from the repo directory name (strip trailing '-ansible')."""
    parent = os.path.basename(os.path.dirname(os.path.abspath(ansible_root))) or 'project'
    if parent.endswith('-ansible'):
        parent = parent[:-len('-ansible')]
    return parent


def _detect_envs(prefix):
    playbooks_dir = os.path.join(prefix, 'playbooks')
    if not os.path.isdir(playbooks_dir):
        return []

    envs = []
    for entry in sorted(os.listdir(playbooks_dir)):
        full = os.path.join(playbooks_dir, entry)
        if not os.path.isdir(full):
            continue
        if not any(name.endswith(YAML_EXTENSIONS) for _, _, files in os.walk(full) for name in files):
            continue
        envs.append(entry)
    return envs


def _detect_paths_for_env(prefix, env):
    """Heuristic: env's own playbook dir, env-named host_vars file, env-named group_vars dir."""
    candidates = [
        ('playbooks/' + env, 'dir'),
        ('inventories/host_vars/' + env + '-server.yml', 'file'),
        ('inventories/group_vars/' + env, 'dir'),
    ]
    paths = []
    for rel, kind in candidates:
        full = os.path.join(prefix, rel)
        if kind == 'dir' and os.path.isdir(full):
            paths.append(rel)
        elif kind == 'file' and os.path.exists(full):
            paths.append(rel)
    return paths


def _detect_existing_secrets(prefix):
    """Collect variable names found inside !vault blocks across the repo."""
    names = set()
    for var_file in get_variables_files(prefix):
        with open(var_file, 'r') as stream:
            for line in stream:
                match = VAULT_BLOCK_RE.match(line)
                if match:
                    names.add(match.group('name'))
    return sorted(names)


def _load_existing_encrypted_variables(prefix):
    cfg_path = os.path.join(prefix, 'encryptor.yml')
    if not os.path.exists(cfg_path):
        return []
    with open(cfg_path, 'r') as stream:
        data = yaml.safe_load(stream) or {}
    return list(data.get('encrypted_variables') or [])


def _render(vault_groups, encrypted_variables):
    lines = ['vault_groups:']
    for group in vault_groups:
        lines.append("  - vault_id: {}".format(group['vault_id']))
        lines.append("    vault_password_file: {}".format(group['vault_password_file']))
        lines.append("    paths:")
        for path in group['paths']:
            lines.append("      - {}".format(path))
        lines.append('')
    lines.append('encrypted_variables:')
    for name in encrypted_variables:
        lines.append('- {}'.format(name))
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description='Generate a v2 encryptor.yml stub by scanning the repo.')
    parser.add_argument('ansible_root', nargs='?', default='../ansible')
    parser.add_argument('--repo-prefix', help='Vault-file name prefix (default: derived from repo dir)')
    options = parser.parse_args()

    prefix = options.ansible_root
    repo_prefix = options.repo_prefix or _detect_repo_prefix(prefix)

    envs = _detect_envs(prefix)
    if not envs:
        sys.exit('encryptor_init: no playbooks/<env>/ subdirs found under {}'.format(prefix))

    vault_groups = []
    for env in envs:
        paths = _detect_paths_for_env(prefix, env)
        if not paths:
            continue
        vault_groups.append({
            'vault_id': env,
            'vault_password_file': '~/.ansible/{}-{}.vault'.format(repo_prefix, env),
            'paths': paths,
        })

    if not vault_groups:
        sys.exit('encryptor_init: detected envs {} but none had matching paths'.format(envs))

    encrypted_variables = _load_existing_encrypted_variables(prefix) or _detect_existing_secrets(prefix)
    if not encrypted_variables:
        sys.stderr.write(
            'encryptor_init: warning: no encrypted_variables found -- '
            'add the secret list manually before running encryptor.py\n'
        )

    sys.stdout.write(_render(vault_groups, encrypted_variables))


if __name__ == '__main__':
    main()
