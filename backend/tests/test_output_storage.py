import unittest
from sqlalchemy.dialects import mysql, sqlite
from models import Scan


class OutputStorageTests(unittest.TestCase):
    def test_mysql_scan_output_has_longtext_capacity(self):
        self.assertEqual(Scan.__table__.c.raw_output.type.compile(dialect=mysql.dialect()), 'LONGTEXT')

    def test_sqlite_remains_supported(self):
        self.assertEqual(Scan.__table__.c.raw_output.type.compile(dialect=sqlite.dialect()), 'TEXT')
