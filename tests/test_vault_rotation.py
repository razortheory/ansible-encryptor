import tempfile
import unittest
from pathlib import Path

from ansible.parsing.vault import AnsibleVaultError, VaultLib, VaultSecret

import encryptor_rotate


class VaultPasswordRotationTests(unittest.TestCase):
    def vault(self, password):
        return VaultLib(secrets=[('prod', VaultSecret(password))])

    def write_blob(self, path, vault, label='prod'):
        encrypted = vault.encrypt(b'fixture-value', vault_id=label)
        path.write_text('TOKEN: !vault |\n' + ''.join(
            '      ' + line + '\n' for line in encrypted.decode().splitlines()
        ))

    def read_blob(self, path):
        return '\n'.join(line.strip() for line in path.read_text().splitlines()[1:])

    def test_same_label_password_change_reencrypts_and_revokes_old_password(self):
        old = self.vault(b'old-ephemeral-password')
        new = self.vault(b'new-ephemeral-password')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'vars.yml'
            self.write_blob(path, old)
            rotated, skipped, failed = encryptor_rotate._rotate_file(str(path), old, new, 'prod')
            self.assertEqual((rotated, skipped, failed), (1, 0, 0))
            blob = self.read_blob(path)
            self.assertEqual(new.decrypt(blob), b'fixture-value')
            with self.assertRaises(AnsibleVaultError):
                old.decrypt(blob)

    def test_already_rotated_file_is_unchanged_on_repeat(self):
        target = self.vault(b'target-ephemeral-password')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'vars.yml'
            self.write_blob(path, target)
            before = path.read_bytes()
            self.assertEqual(encryptor_rotate._rotate_file(str(path), target, target, 'prod'), (0, 1, 0))
            self.assertEqual(path.read_bytes(), before)

    def test_legacy_blob_migrates_without_changing_value(self):
        old = self.vault(b'legacy-ephemeral-password')
        new = self.vault(b'new-ephemeral-password')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'vars.yml'
            self.write_blob(path, old, label=None)
            self.assertEqual(encryptor_rotate._rotate_file(str(path), old, new, 'prod'), (1, 0, 0))
            blob = self.read_blob(path)
            self.assertTrue(blob.startswith('$ANSIBLE_VAULT;1.2;AES256;prod\n'))
            self.assertEqual(new.decrypt(blob), b'fixture-value')


if __name__ == '__main__':
    unittest.main()
