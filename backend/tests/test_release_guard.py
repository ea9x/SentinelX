import importlib.util
from pathlib import Path
import tempfile
import unittest

script=Path(__file__).resolve().parents[2]/'scripts/check_release.py'
spec=importlib.util.spec_from_file_location('check_release',script)
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)

class ReleaseGuardTests(unittest.TestCase):
    def make_source(self,root):
        for name in ['README.md','.gitignore','SECURITY.md','backend/.env.example','.env.example','frontend/package-lock.json']:
            file=root/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_text('')

    def test_clean_source_and_private_configuration_detection(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);self.make_source(root)
            self.assertEqual(release.check(root)[1],[])
            (root/'backend/.env').write_text('private-fixture')
            self.assertIn('backend/.env',[name for name,_ in release.check(root)[1]])

    def test_example_secrets_and_credential_tokens_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);self.make_source(root)
            (root/'.env.example').write_text('SECRET_KEY=not-a-real-secret\n')
            (root/'token.txt').write_text('ghp_'+'x'*40)
            findings=release.check(root)[1]
            self.assertTrue(any(name=='.env.example' for name,_ in findings))
            self.assertTrue(any(name=='token.txt' for name,_ in findings))

    def test_backups_and_generated_reports_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);self.make_source(root)
            (root/'backend/generated_reports').mkdir()
            (root/'backend/generated_reports/private.pdf').write_bytes(b'fixture')
            self.assertTrue(release.check(root)[1])
