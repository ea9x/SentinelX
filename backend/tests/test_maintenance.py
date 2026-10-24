from datetime import datetime
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from cryptography.fernet import Fernet, InvalidToken
from models import db
import maintenance


class MaintenanceTests(unittest.TestCase):
    def test_encrypted_backup_restores_exact_rows_in_disposable_sqlite(self):
        cipher=Fernet(Fernet.generate_key())
        tables={table.name:[] for table in db.metadata.sorted_tables}
        tables['users']=[{'id':1,'username':'fixture','email':'fixture@example.test','password_hash':'fixture-hash','role':'analyst',
                          'avatar_icon':'shield','avatar_color':'#38bdf8','avatar_url':None,'is_active':True,'created_at':datetime(2026,10,22,12,0)}]
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as archive:
            archive.writestr('database.json',json.dumps({'format':1,'tables':tables},default=maintenance._encode))
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            folder=Path(directory);path=folder/'fixture.sxbackup';path.write_bytes(cipher.encrypt(stream.getvalue()))
            self.assertNotIn(b'fixture@example.test',path.read_bytes())
            with patch.object(maintenance,'RESTORE',folder),patch.object(maintenance,'_key',return_value=cipher):
                result=maintenance.verify(path)
            self.assertEqual(result['rows'],1)
            self.assertEqual(list(folder.glob('restore-check-*.sqlite')),[])

    def test_tampered_backup_is_rejected_before_restore(self):
        cipher=Fernet(Fernet.generate_key())
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            folder=Path(directory);path=folder/'fixture.sxbackup';path.write_bytes(b'invalid-ciphertext')
            with patch.object(maintenance,'RESTORE',folder),patch.object(maintenance,'_key',return_value=cipher):
                with self.assertRaises(InvalidToken): maintenance.verify(path)
            self.assertEqual(list(folder.glob('restore-check-*.sqlite')),[])
