import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
from unittest.mock import patch
from scanners.api_scanner import run_api_scan
from scanners import zap_scanner
from scan_options import validate_options, encrypt_options, decrypt_options
from flask import Flask


class Handler(BaseHTTPRequestHandler):
    cross_allowed=True
    seen=[]
    def log_message(self,*args): pass
    def do_POST(self):
        length=int(self.headers.get('Content-Length',0))
        body=json.loads(self.rfile.read(length))
        token='token-a' if body['email']=='a@example.test' else 'token-b'
        self.send(200,{'authentication':{'token':token}})
    def send(self,status,body,mime='application/json'):
        self.send_response(status);self.send_header('Content-Type',mime)
        self.send_header('Set-Cookie','session=token-b')
        self.end_headers();self.wfile.write((json.dumps(body) if not isinstance(body,str) else body).encode())
    def do_GET(self):
        parsed=urlsplit(self.path);path=parsed.path;auth=self.headers.get('Authorization','')
        Handler.seen.append((self.path,auth))
        if path=='/spec.yaml':
            return self.send(200,'openapi: 3.0.0\nservers:\n  - url: https://untrusted.invalid/api\npaths:\n  /items:\n    get: {}\n  /write:\n    post: {}\n  /objects/{id}:\n    get: {}\n','text/yaml')
        if path=='/api/items': return self.send(200,{'items':[]})
        if path=='/metrics': return self.send(200,'# HELP sample Sample\n# TYPE sample counter\nsample 1','text/plain')
        if path=='/ftp/': return self.send(200,'<title>Listing directory /ftp/</title><a href="secret.md">secret.md</a>','text/html')
        if path=='/ftp/secret.md': return self.send(200,'CONFIDENTIAL document','text/plain')
        if path=='/search':
            return self.send(500,'SQLITE_ERROR: near token') if "'" in parse_qs(parsed.query).get('q',[''])[0] else self.send(200,[])
        if path=='/redirect':
            self.send_response(302);self.send_header('Location','https://untrusted.invalid/');self.end_headers();return
        if path.startswith('/private/') or path=='/public/b':
            owner=path[-1]
            if path=='/public/b': return self.send(200,'owned-marker-b')
            if not auth: return self.send(401,{})
            if owner=='b' and auth=='Bearer token-a' and not Handler.cross_allowed: return self.send(403,{})
            if auth not in {'Bearer token-a','Bearer token-b'}: return self.send(401,{})
            return self.send(200,'owned-marker-'+owner)
        return self.send(404,{})


def options():
    return {'openapi_path':'/spec.yaml','query_checks':['/search?q=orange'],
            'accounts':[{'login':{'path':'/login','json':{'email':who+'@example.test','password':'fixture-secret'},'token_field':'authentication.token'},
                         'verify_path':'/private/'+who,'verify_marker':'owned-marker-'+who} for who in ['a','b']],
            'authorization_checks':[{'path_a':'/private/a','path_b':'/private/b','marker_a':'owned-marker-a','marker_b':'owned-marker-b'}]}


class CoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.url='http://127.0.0.1:'+str(cls.server.server_port)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def setUp(self):
        Handler.cross_allowed=True;Handler.seen=[]
    def test_api_import_login_exposure_and_two_account_access(self):
        result=run_api_scan(self.url,options())
        self.assertTrue(result['success'],result)
        self.assertEqual(len(result['vulnerabilities']),5)
        self.assertIn('/api/items',result['paths'])
        self.assertNotIn('/api/write',[p for p,_ in Handler.seen])
        self.assertTrue(any(o.get('authenticated_verification')=='passed' for o in result['observations']))
        exported=json.dumps(result)
        for secret in ['fixture-secret','token-a','token-b','owned-marker-b']: self.assertNotIn(secret,exported)
    def test_denied_cross_user_access_is_not_flagged(self):
        Handler.cross_allowed=False
        result=run_api_scan(self.url,options())
        self.assertTrue(result['success'])
        self.assertFalse(any(f['cve_id']=='CWE-639' for f in result['vulnerabilities']))
    def test_public_resource_is_not_idor(self):
        value=options();value['authorization_checks'][0]['path_b']='/public/b'
        result=run_api_scan(self.url,value)
        self.assertFalse(any(f['cve_id']=='CWE-639' for f in result['vulnerabilities']))
    def test_failed_authentication_is_not_a_clean_scan(self):
        value=options();value['accounts'][0]={'headers':{'Authorization':'Bearer invalid-secret'},'verify_path':'/private/a','verify_marker':'owned-marker-a'}
        result=run_api_scan(self.url,value)
        self.assertFalse(result['success']);self.assertNotIn('invalid-secret',json.dumps(result))
    def test_redirect_is_not_followed(self):
        result=run_api_scan(self.url,{'openapi_path':'/spec.yaml','paths':['/redirect']})
        self.assertTrue(result['success'])
        self.assertIn('/redirect',result['paths'])
    def test_html_page_is_not_an_openapi_definition(self):
        result=run_api_scan(self.url,{'openapi_path':'/ftp/'})
        self.assertFalse(result['success'])
    def test_rejects_external_paths_and_injected_headers(self):
        for path in ['https://other.test/x','//other.test/x','/%2fother.test','/../a','/x%0d%0aHost:test','/x\\other']:
            with self.assertRaises(ValueError): validate_options({'paths':[path]})
        value=options();value['accounts'][0]={'headers':{'Host':'other.test'},'verify_path':'/private/a','verify_marker':'owned-marker-a'}
        with self.assertRaises(ValueError): validate_options(value)
    def test_options_encrypted_and_tamper_evident(self):
        app=Flask(__name__);app.config['SECRET_KEY']='isolated-test-key'
        with app.app_context():
            encrypted=encrypt_options(options());self.assertNotIn('fixture-secret',encrypted)
            self.assertEqual(decrypt_options(encrypted),options())
            with self.assertRaises(Exception): decrypt_options(encrypted[:-4]+'abcd')
    def test_zap_timeout_keeps_partial_results_and_failed_state(self):
        finding={'title':'Known exposure','cve_id':'CWE-200'}
        with patch.object(zap_scanner,'_zap_get',return_value={'version':'test'}),patch.object(zap_scanner,'run_api_scan',return_value={'success':True,'vulnerabilities':[finding],'observations':[]}),patch.object(zap_scanner,'_run_spider',return_value={'success':True}),patch.object(zap_scanner,'_run_active_scan',return_value={'success':False,'error':'timed out'}),patch.object(zap_scanner,'_get_alerts',return_value=[]):
            result=zap_scanner.run_zap_scan(self.url)
        self.assertFalse(result['success']);self.assertEqual(result['vulnerabilities'],[finding])
