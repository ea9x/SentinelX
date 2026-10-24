import importlib.util
from pathlib import Path
import tempfile
import unittest

script=Path(__file__).resolve().parents[2]/'scripts/configure_local.py'
spec=importlib.util.spec_from_file_location('configure_local',script)
configure=importlib.util.module_from_spec(spec);spec.loader.exec_module(configure)

class ConfigurationTests(unittest.TestCase):
    def test_private_keys_are_unique_and_existing_configuration_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'backend').mkdir()
            (root/'backend/.env.example').write_text('SECRET_KEY=\nZAP_API_KEY=\nDB_PASSWORD=\n')
            destination=configure.configure(root)
            original=destination.read_text();values=dict(line.split('=',1) for line in original.splitlines())
            self.assertEqual(len(values['SECRET_KEY']),64)
            self.assertNotEqual(values['SECRET_KEY'],values['ZAP_API_KEY'])
            self.assertEqual(values['DB_PASSWORD'],'')
            with self.assertRaises(FileExistsError):configure.configure(root)
            self.assertEqual(destination.read_text(),original)
