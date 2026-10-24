import json
import subprocess
import unittest
from unittest.mock import patch
from scanners import nuclei_scanner, zap_scanner, whatweb_scanner
import requests


class ScannerFailureTests(unittest.TestCase):
    def test_zap_cancel_stops_the_owned_scan(self):
        from job_control import ScanCancelled
        with patch.object(zap_scanner,'check_cancelled',side_effect=ScanCancelled()),patch.object(zap_scanner,'_zap_get',return_value={}) as request:
            with self.assertRaises(ScanCancelled): zap_scanner._wait_for_scan('/JSON/ascan/view/status/','owned-scan',30)
        request.assert_called_once_with('/JSON/ascan/action/stop/',scanId='owned-scan',timeout=5)

    def test_native_user_scan_handles_scan_as_user_response(self):
        token=zap_scanner._scan_context.set({'id':'context-1','user':'user-1'})
        try:
            with patch.object(zap_scanner,'_zap_get',return_value={'scanAsUser':'42'}) as request,patch.object(zap_scanner,'_wait_for_scan',return_value={'success':True}) as wait:
                self.assertTrue(zap_scanner._run_spider('http://127.0.0.1')['success'])
                self.assertEqual(request.call_args.args[0],'/JSON/spider/action/scanAsUser/')
                self.assertEqual(wait.call_args.args[1],'42')
        finally: zap_scanner._scan_context.reset(token)
    def test_zap_http_error_does_not_expose_api_key(self):
        response = requests.Response()
        response.status_code = 400
        response.url = 'http://localhost/?apikey=private-secret'
        with patch.object(zap_scanner.requests, 'get', return_value=response):
            with self.assertRaisesRegex(RuntimeError, 'HTTP 400') as caught:
                zap_scanner._zap_get('/JSON/core/view/version/')
        self.assertNotIn('private-secret', str(caught.exception))
        self.assertNotIn('apikey', str(caught.exception))

    def test_zap_connection_error_does_not_expose_api_key(self):
        with patch.object(zap_scanner.requests, 'get', side_effect=requests.ConnectionError('apikey=private-secret')):
            with self.assertRaises(RuntimeError) as caught:
                zap_scanner._zap_get('/JSON/core/view/version/')
        self.assertNotIn('private-secret', str(caught.exception))

    def run_nuclei(self, code=0, stdout='', stderr=''):
        with patch.object(nuclei_scanner.Path, 'is_file', return_value=True), patch.object(
            nuclei_scanner.subprocess, 'run', return_value=subprocess.CompletedProcess([],code,stdout,stderr)
        ) as process:
            result=nuclei_scanner.run_nuclei_scan('http://127.0.0.1:18092')
            return result,process.call_args

    def test_exit_one_is_a_failure(self):
        result,_=self.run_nuclei(1,stderr='FATAL: no templates available')
        self.assertFalse(result['success'])
        self.assertEqual(result['exit_code'],1)
        self.assertIn('no templates',result['error'])

    def test_nonzero_with_partial_findings_is_still_failure(self):
        finding=json.dumps({'template-id':'test-template','info':{'name':'Sample','severity':'low'},'matched-at':'http://127.0.0.1:18092/'})
        result,_=self.run_nuclei(2,stdout=finding,stderr='FATAL: interrupted')
        self.assertFalse(result['success'])
        self.assertEqual(len(result['vulnerabilities']),1)
        self.assertEqual(result['raw_output'],finding)

    def test_empty_success_has_no_stdin_or_update_wait(self):
        result,call=self.run_nuclei()
        self.assertTrue(result['success'])
        self.assertEqual(result['vulnerabilities'],[])
        for flag in ['-no-stdin','-disable-update-check','-no-interactsh']:
            self.assertIn(flag,call.args[0])
        self.assertEqual(call.kwargs['stdin'],subprocess.DEVNULL)

    def test_timeout_is_a_failure(self):
        with patch.object(nuclei_scanner.Path,'is_file',return_value=True),patch.object(
            nuclei_scanner.subprocess,'run',side_effect=subprocess.TimeoutExpired([],300)
        ):
            self.assertFalse(nuclei_scanner.run_nuclei_scan('http://127.0.0.1')['success'])

    def test_invalid_json_is_not_an_empty_success(self):
        for output in ['not-json', '[]', '{"info": ["unexpected"]}']:
            result,_=self.run_nuclei(stdout=output)
            self.assertFalse(result['success'],output)

    def test_whatweb_failure_with_stdout_is_not_success(self):
        with patch.object(whatweb_scanner.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'HTTPServer[Test]','tool failed')):
            result=whatweb_scanner.run_whatweb_scan('http://127.0.0.1')
        self.assertFalse(result['success'])
        self.assertIn('tool failed',result['error'])

    def test_zap_timeout_stops_only_its_scan(self):
        with patch.object(zap_scanner,'_zap_get',return_value={}) as request:
            result=zap_scanner._wait_for_scan('/JSON/ascan/view/status/','scan-123',0)
        self.assertFalse(result['success'])
        request.assert_called_once_with('/JSON/ascan/action/stop/',scanId='scan-123',timeout=5)

    def test_zap_completion_does_not_stop_scan(self):
        with patch.object(zap_scanner,'_zap_get',return_value={'status':'100'}) as request:
            self.assertTrue(zap_scanner._wait_for_scan('/JSON/spider/view/status/','scan-123',10)['success'])
        self.assertEqual(request.call_count,1)

    def test_zap_api_failure_attempts_cleanup(self):
        with patch.object(zap_scanner,'_zap_get',side_effect=[ValueError('bad response'),{}]) as request:
            with self.assertRaises(ValueError):
                zap_scanner._wait_for_scan('/JSON/spider/view/status/','scan-123',10)
        self.assertEqual(request.call_args.args[0],'/JSON/spider/action/stop/')
