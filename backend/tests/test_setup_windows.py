import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from dotenv import dotenv_values

scripts=Path(__file__).resolve().parents[2]/'scripts'
sys.path.insert(0,str(scripts))
try:
    spec=importlib.util.spec_from_file_location('setup_windows',scripts/'setup_windows.py')
    setup=importlib.util.module_from_spec(spec);spec.loader.exec_module(setup)
finally:
    sys.path.remove(str(scripts))

class SetupTests(unittest.TestCase):
    def test_trial_configuration_uses_a_private_database_and_never_overwrites_existing_settings(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root=Path(directory);(root/'backend').mkdir()
            (root/'backend/.env.example').write_text('SECRET_KEY=\nZAP_API_KEY=\nDB_PASSWORD=\n')
            self.assertTrue(setup.create_configuration(root,'sqlite'))
            values=dotenv_values(root/'backend/.env')
            self.assertEqual(len(values['SECRET_KEY']),64)
            self.assertTrue(values['DATABASE_URL'].endswith('/.local/sentinelx.sqlite'))
            original=(root/'backend/.env').read_bytes()
            self.assertFalse(setup.create_configuration(root,'mysql',{'DB_PASSWORD':'different'}))
            self.assertEqual(original,(root/'backend/.env').read_bytes())

    def test_incomplete_mysql_configuration_does_not_create_private_file(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root=Path(directory);(root/'backend').mkdir()
            with self.assertRaises(ValueError):setup.create_configuration(root,'mysql',{'DB_HOST':'127.0.0.1'})
            self.assertFalse((root/'backend/.env').exists())

    def test_missing_node_is_reported_before_installation(self):
        with patch.object(setup.sys,'version_info',(3,12,0)),patch.object(setup.shutil,'which',return_value=None):
            _,_,problems=setup.prerequisites()
            self.assertTrue(any('Node.js' in item for item in problems))

    def test_bootstrap_environment_cannot_inherit_an_unrelated_database(self):
        with patch.dict(os.environ,{'DATABASE_URL':'sqlite:///unrelated-test.sqlite','SECRET_KEY':'synthetic-unrelated-setting','PATH':'keep-this-path'}):
            child=setup.child_environment()
            self.assertNotIn('DATABASE_URL',child);self.assertNotIn('SECRET_KEY',child)
            self.assertEqual(child['PATH'],'keep-this-path')
