import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess,TimeoutExpired
from unittest.mock import patch
from scanners import whatweb_scanner as scanner


class WhatWebRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.environment=patch.dict(scanner.os.environ,{'RUBY_PATH':''});self.environment.start()
    def tearDown(self):
        scanner._probe_runtime.cache_clear();self.environment.stop()

    def test_explicit_runtime_is_used_for_health_and_scan(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'whatweb';path.write_text('fixture')
            with patch.dict(scanner.os.environ,{'RUBY_PATH':'configured-ruby.exe'}),patch.object(scanner,'WHATWEB_PATH',path),patch.object(scanner.subprocess,'run',return_value=CompletedProcess([],0,'WhatWeb version 0.6','')) as run:
                self.assertTrue(scanner.check_whatweb_runtime()['available'])
                self.assertTrue(scanner.run_whatweb_scan('http://127.0.0.1:1')['success'])
                self.assertEqual(run.call_count,2)
                self.assertTrue(all(call.args[0][0]=='configured-ruby.exe' for call in run.call_args_list))

    def test_invalid_explicit_runtime_never_falls_back_silently(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'whatweb';path.write_text('fixture')
            with patch.dict(scanner.os.environ,{'RUBY_PATH':'missing-ruby.exe'}),patch.object(scanner.shutil,'which') as which,patch.object(scanner.subprocess,'run',side_effect=FileNotFoundError):
                self.assertFalse(scanner.check_whatweb_runtime(path)['available']);which.assert_not_called()

    def test_present_but_blocked_runtime_is_unavailable_and_cached(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'whatweb';path.write_text('fixture')
            blocked=CompletedProcess([],1,'','An Application Control policy has blocked this file. private/digest.so')
            with patch.object(scanner.shutil,'which',return_value='ruby'),patch.object(scanner.subprocess,'run',return_value=blocked) as run:
                first=scanner.check_whatweb_runtime(path);second=scanner.check_whatweb_runtime(path)
                self.assertFalse(first['available']);self.assertEqual(first,second)
                self.assertEqual(first['error'],scanner.BLOCKED_MESSAGE);self.assertNotIn('private',first['error'])
                run.assert_called_once()

    def test_success_timeout_and_missing_runtime_are_distinct(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'whatweb';path.write_text('fixture')
            with patch.object(scanner.shutil,'which',return_value='ruby'),patch.object(scanner.subprocess,'run',return_value=CompletedProcess([],0,'WhatWeb version 0.6','')):
                self.assertTrue(scanner.check_whatweb_runtime(path)['available'])
            scanner._probe_runtime.cache_clear()
            with patch.object(scanner.shutil,'which',return_value='ruby'),patch.object(scanner.subprocess,'run',side_effect=TimeoutExpired('ruby',5)):
                self.assertFalse(scanner.check_whatweb_runtime(path)['available'])
            with patch.object(scanner.shutil,'which',return_value=None):
                self.assertIn('not found',scanner.check_whatweb_runtime(path)['error'])

    def test_blocked_scan_keeps_diagnostics_separate_from_public_error(self):
        with patch.object(scanner.subprocess,'run',return_value=CompletedProcess([],1,'','An Application Control policy has blocked this file. private/digest.so')):
            result=scanner.run_whatweb_scan('http://127.0.0.1:18094')
        self.assertFalse(result['success']);self.assertEqual(result['error'],scanner.BLOCKED_MESSAGE)
        self.assertIn('private/digest.so',result['stderr'])
