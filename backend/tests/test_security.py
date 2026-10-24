"""Isolated integration tests. Never connects to the user's MySQL database."""
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SECRET_KEY"] = "sentinelx-integration-test-secret-at-least-32-characters"
from app import app
from models import db, User, Target, Scan, Vulnerability, PasswordReset, ScanJob
from routes.auth import bcrypt
from scan_worker import process_next_job, recover_interrupted_jobs
import report_generator
import routes.reports as reports_module


class SentinelXTests(unittest.TestCase):
    def test_profile_photo_upload_is_retired(self):
        from routes.auth import AVATAR_DIRECTORY
        before={path.name for path in AVATAR_DIRECTORY.iterdir()}
        response=self.mutate('post','/api/auth/avatar',{})
        self.assertEqual(response.status_code,410)
        self.assertIn('no longer supported',response.get_json()['error'])
        self.assertEqual(before,{path.name for path in AVATAR_DIRECTORY.iterdir()})

    def test_target_management_validation_duplicates_and_ownership(self):
        payload = {"name":"Example", "hostname":"EXAMPLE.test.", "port":443}
        response = self.mutate('post','/api/targets/',payload)
        self.assertEqual(response.status_code,201)
        item = response.get_json()['target']
        self.assertEqual(item['hostname'],'example.test')
        self.assertEqual(self.mutate('post','/api/targets/',payload).status_code,409)
        self.assertEqual(self.mutate('put',f"/api/targets/{item['id']}",{**payload,'name':'Renamed'}).status_code,200)
        self.assertEqual(self.mutate('put',f"/api/targets/{self.target(self.b).id}",payload).status_code,404)
        self.assertEqual(self.mutate('post','/api/targets/',{**payload,'port':0}).status_code,400)
        self.assertEqual(self.mutate('post','/api/targets/',{**payload,'hostname':'https://bad/path'}).status_code,400)
        self.assertEqual(self.mutate('delete',f"/api/targets/{item['id']}").status_code,200)

    def test_target_history_remains_attached_and_summary_counts_latest_scan(self):
        target = self.target()
        scan = self.scan(target)
        item = next(x for x in self.client.get('/api/targets/').get_json() if x['id']==target.id)
        self.assertTrue(item['has_history'])
        self.assertEqual(item['last_scan']['id'],scan.id)
        self.assertEqual(item['last_scan']['findings']['Low'],1)
        payload = {'name':'Renamed','ip_address':'127.0.0.1','port':443}
        self.assertEqual(self.mutate('put',f'/api/targets/{target.id}',payload).status_code,200)
        self.assertEqual(self.mutate('put',f'/api/targets/{target.id}',{**payload,'port':80}).status_code,409)
        self.assertEqual(self.mutate('delete',f'/api/targets/{target.id}').status_code,200)
        self.assertFalse(any(x['id']==target.id for x in self.client.get('/api/targets/').get_json()))
        self.assertEqual(self.mutate('post',f'/api/scans/nmap/{target.id}',{}).status_code,404)
        self.assertEqual(self.client.get(f'/api/scans/{scan.id}').status_code,200)
        self.assertEqual(Scan.query.count(),1)
        self.assertEqual(Vulnerability.query.count(),1)

    def test_target_delete_blocks_active_scans_and_other_owners(self):
        target = self.target()
        db.session.add(ScanJob(id='delete-active-test', user_id=self.a.id, target_id=target.id, tool='nmap',status='queued'))
        db.session.commit()
        self.assertEqual(self.mutate('delete',f'/api/targets/{target.id}').status_code,409)
        self.assertFalse(target.is_deleted)
        other = self.target(self.b)
        self.assertEqual(self.mutate('delete',f'/api/targets/{other.id}').status_code,404)

    def test_scanner_connection_errors_are_clear_and_diagnostics_retained(self):
        from routes.scans import _run_full_sslyze, _run_full_whatweb
        target = self.target()
        trace = 'Traceback File "D:/private/tool.py" ServerRejectedConnection: Server rejected the connection'
        with patch('routes.scans.run_sslyze_scan',return_value={'success':False,'error':trace}):
            summary,count = _run_full_sslyze(target)
        self.assertEqual(summary['status'],'failed')
        self.assertEqual(count,0)
        self.assertIn('refused the connection',summary['error'])
        self.assertNotIn('Traceback',summary['error'])
        self.assertIn(trace,db.session.get(Scan,summary['scan_id']).raw_output)
        with patch('routes.scans.run_whatweb_scan',return_value={'success':False,'error':'No connection could be made because the target machine actively refused it'}):
            summary,_ = _run_full_whatweb(target)
        self.assertIn('service is running',summary['error'])

    def test_auth_rate_limit_cannot_be_bypassed_by_forwarded_header(self):
        from security import LIMITS
        from models import AuthRateLimit
        AuthRateLimit.query.delete(); db.session.commit()
        with patch.dict(LIMITS, {'auth.login':(2,60)}):
            for n in range(2):
                self.assertEqual(self.client.post('/api/auth/login',json={'email':'none@example.test','password':'bad'},headers={'X-Forwarded-For':str(n)}).status_code,401)
            blocked=self.client.post('/api/auth/login',json={'email':'none@example.test','password':'bad'},headers={'X-Forwarded-For':'third'})
            self.assertEqual(blocked.status_code,429)
            self.assertGreater(int(blocked.headers['Retry-After']),0)

    def test_request_limit_security_headers_origin_and_registration(self):
        response=self.client.post('/api/auth/login',data='x'*65537,content_type='application/json')
        self.assertEqual(response.status_code,413)
        self.assertEqual(response.headers['X-Content-Type-Options'],'nosniff')
        self.assertEqual(response.headers['Cache-Control'],'no-store')
        rejected=self.client.post('/api/auth/login',json={},headers={'Origin':'https://untrusted.test'})
        self.assertEqual(rejected.status_code,403)
        with patch.dict(app.config, {'ALLOW_REGISTRATION':False}):
            self.assertEqual(self.client.post('/api/auth/register',json={'username':'visitor','email':'visitor@example.test','password':'Password123!'}).status_code,403)
        self.assertEqual(self.client.get('/api/auth/avatars/nonexistent.webp').status_code,404)
        self.assertEqual(app.test_client().get('/api/auth/avatars/nonexistent.webp').status_code,401)

    def test_injection_inputs_are_data_and_scanner_options_stay_bounded(self):
        from scan_options import validate_options
        for address in ['127.0.0.1;whoami','-oN output','$(whoami)','127.0.0.1/24','localhost && whoami']:
            self.assertEqual(self.mutate('post','/api/targets/',{'name':'test','hostname':address}).status_code,400)
        response=self.client.post('/api/auth/login',json={'email':"x' OR 1=1 --",'password':'test'})
        self.assertEqual(response.status_code,401)
        for path in ['//evil.test/','/%2f%2fevil.test','/../admin','/a/%2e%2e/admin','/a%0d%0aHost:evil','/\\evil']:
            with self.assertRaises(ValueError): validate_options({'paths':[path]})

    def test_readiness_requires_owner_and_keeps_closed_ports_explicit(self):
        target=self.target()
        with patch('readiness.inspect_target',return_value={'tcp_open':False,'http':False,'tls':False,'message':'closed'}) as inspect:
            self.assertEqual(self.mutate('post',f'/api/targets/{self.target(self.b).id}/readiness',{}).status_code,404)
            inspect.assert_not_called()
            response=self.mutate('post',f'/api/targets/{target.id}/readiness',{})
            self.assertEqual(response.status_code,200)
            self.assertFalse(response.get_json()['tcp_open'])
            inspect.assert_called_once_with('127.0.0.1',443)

    def setUp(self):
        app.config.update(TESTING=True, JWT_COOKIE_SECURE=False, ALLOW_REGISTRATION=True,
                          PUBLIC_APP_URL="http://localhost:8088", RESET_TTL_SECONDS=900)
        self.context = app.app_context()
        self.context.push()
        db.drop_all()
        db.create_all()
        self.a = User(username="analyst-a", email="a@example.test",
                      password_hash=bcrypt.generate_password_hash("Password123!").decode())
        self.b = User(username="analyst-b", email="b@example.test",
                      password_hash=bcrypt.generate_password_hash("Password123!").decode())
        self.admin = User(username="admin", email="admin@example.test", role="admin",
                          password_hash=bcrypt.generate_password_hash("Password123!").decode())
        db.session.add_all([self.a, self.b, self.admin])
        db.session.commit()
        self.client = app.test_client()
        self.login(self.client)
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        report_root = Path(self.temp.name)/"generated_reports"
        report_root.mkdir()
        self.patches = [patch.object(report_generator, "REPORTS_DIRECTORY", report_root),
                        patch.object(reports_module, "REPORTS_DIRECTORY", report_root)]
        for item in self.patches: item.start()

    def tearDown(self):
        for item in self.patches: item.stop()
        self.temp.cleanup()
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def login(self, client, email="a@example.test", password="Password123!"):
        response = client.post("/api/auth/login", json={"email": email, "password": password})
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertNotIn("requires_otp", response.get_json())
        return response

    def mutate(self, method, url, data=None, client=None):
        client = client or self.client
        csrf = client.get_cookie("sentinelx_csrf")
        return getattr(client, method)(url, json=data,
            headers={"X-CSRF-TOKEN": csrf.value if csrf else ""})

    def target(self, user=None, name="Local test"):
        target = Target(name=name, ip_address="127.0.0.1", port=443,
                        added_by=(user or self.a).id)
        db.session.add(target)
        db.session.commit()
        return target

    def scan(self, target):
        scan = Scan(target_id=target.id, tool_used="nmap", status="completed",
                    started_at=datetime.utcnow(), finished_at=datetime.utcnow(),
                    raw_output="443/tcp open https Test Server")
        db.session.add(scan)
        db.session.flush()
        db.session.add(Vulnerability(scan_id=scan.id, title="Test finding",
                                    severity="Low", source_tool="nmap",
                                    description="A sample finding", evidence="test evidence",
                                    affected_port=443, ai_recommendation="Review configuration."))
        db.session.commit()
        return scan

    def test_password_login_needs_no_mail_and_removed_otp_routes(self):
        with patch("routes.auth.send_password_reset_link") as send:
            self.login(app.test_client(), email="A@example.test")
            send.assert_not_called()
        for path in ["verify-otp", "resend-otp"]:
            self.assertEqual(self.client.post("/api/auth/login/"+path, json={}).status_code, 404)
        self.assertEqual(self.client.post("/api/auth/login", json={"email":"a@example.test", "password":"wrong"}).status_code,401)
        self.a.is_active=False
        db.session.commit()
        self.assertEqual(self.client.post("/api/auth/login", json={"email":"a@example.test", "password":"Password123!"}).status_code,403)

    def test_cookie_csrf_and_unauthenticated_access(self):
        public=app.test_client()
        for path in ["/api/targets/", "/api/scans/", "/api/vulnerabilities/", "/api/reports/", "/api/health"]:
            self.assertEqual(public.get(path).status_code,401,path)
        self.assertEqual(self.client.post("/api/targets/", json={"name":"test", "hostname":"localhost"}).status_code,401)
        cookie=self.client.get_cookie("sentinelx_access",path="/api/")
        self.assertTrue(cookie.http_only)

    def test_all_lists_and_statistics_are_owner_scoped(self):
        mine=self.target()
        other=self.target(self.b,"Other private target")
        self.scan(mine)
        foreign=self.scan(other)
        for path in ["/api/targets/", "/api/scans/", "/api/vulnerabilities/"]:
            response=self.client.get(path)
            self.assertEqual(response.status_code,200)
            self.assertEqual(len(response.get_json()),1,path)
            self.assertNotIn("Other private target",response.get_data(as_text=True))
        self.assertEqual(self.client.get("/api/vulnerabilities/stats").get_json()["total"],1)
        self.assertEqual(self.client.get(f"/api/scans/{foreign.id}").status_code,404)
        self.assertEqual(self.mutate("delete",f"/api/targets/{other.id}").status_code,404)
        for tool in ["nmap","zap","whatweb","nuclei","sslyze","full"]:
            self.assertEqual(self.mutate("post",f"/api/scans/{tool}/{other.id}").status_code,404)

    def test_target_validation_and_safe_delete(self):
        for data in [[], {"name":"x"}, {"name":"x","hostname":"-bad"},
                     {"name":"x","hostname":"https://example.test"},
                     {"name":"x","ip_address":"invalid"},
                     {"name":"x","hostname":"localhost","port":70000},
                     {"name":"x","hostname":"localhost","port":True}]:
            self.assertEqual(self.mutate("post","/api/targets/",data).status_code,400,str(data))
        response=self.mutate("post","/api/targets/",{"name":"IPv6", "ip_address":"::1", "port":443})
        self.assertEqual(response.status_code,201)
        target_id=response.get_json()["target"]["id"]
        self.assertEqual(self.mutate("delete",f"/api/targets/{target_id}").status_code,200)
        target=self.target()
        self.scan(target)
        self.assertEqual(self.mutate("delete",f"/api/targets/{target.id}").status_code,200)

    def test_password_reset_link_expiry_replay_and_session_revocation(self):
        with patch("routes.auth.send_password_reset_link") as send:
            response=self.client.post("/api/auth/password/forgot",json={"email":"a@example.test"})
            self.assertEqual(response.status_code,202)
            self.assertNotIn("token",response.get_json())
            token=send.call_args.args[1].split("#token=")[1]
        self.assertNotIn(token,PasswordReset.query.one().challenge_hash)
        response=self.client.post("/api/auth/password/reset",json={"token":token,"new_password":"Replacement123!"})
        self.assertEqual(response.status_code,200,response.get_json())
        self.assertEqual(self.client.get("/api/auth/me").status_code,403)
        self.assertEqual(self.client.post("/api/auth/password/reset",json={"token":token,"new_password":"Replacement456!"}).status_code,401)
        self.login(app.test_client(),password="Replacement123!")
        with patch("routes.auth.send_password_reset_link") as send:
            self.client.post("/api/auth/password/forgot",json={"email":"a@example.test"})
            token=send.call_args.args[1].split("#token=")[1]
        record=PasswordReset.query.order_by(PasswordReset.id.desc()).first()
        record.expires_at=datetime.utcnow()-timedelta(seconds=1)
        db.session.commit()
        self.assertEqual(self.client.post("/api/auth/password/reset",json={"token":token,"new_password":"Replacement456!"}).status_code,401)

    def test_reset_email_failures_do_not_reveal_account_existence(self):
        with patch("routes.auth.send_password_reset_link", side_effect=RuntimeError("test SMTP unavailable")):
            known=self.client.post("/api/auth/password/forgot",json={"email":"a@example.test"})
        unknown=self.client.post("/api/auth/password/forgot",json={"email":"unknown@example.test"})
        self.assertEqual(known.status_code,202)
        self.assertEqual(known.get_json(),unknown.get_json())
        self.assertEqual(PasswordReset.query.count(),0)

    def test_logout_revokes_copied_cookie(self):
        stolen=self.client.get_cookie("sentinelx_access",path="/api/").value
        response=self.mutate("post","/api/auth/logout",{})
        self.assertEqual(response.status_code,200)
        replay=app.test_client()
        replay.set_cookie("sentinelx_access",stolen,path="/api/")
        self.assertEqual(replay.get("/api/auth/me").status_code,403)

    def test_analyst_can_edit_own_profile_and_password_not_admin_controls(self):
        self.assertEqual(self.client.get("/api/users").status_code,403)
        response=self.mutate("put","/api/auth/profile",{"username":"new-analyst", "current_password":"Password123!"})
        self.assertEqual(response.status_code,200,response.get_json())
        old_client=app.test_client()
        self.login(old_client)
        response=self.mutate("put","/api/auth/password",{"current_password":"Password123!", "new_password":"ChangedPassword123!"})
        self.assertEqual(response.status_code,200,response.get_json())
        self.assertEqual(self.client.get("/api/auth/me").status_code,200)
        self.assertEqual(old_client.get("/api/auth/me").status_code,403)

    def test_report_generation_download_and_owner_isolation(self):
        scan=self.scan(self.target())
        created=self.mutate("post","/api/reports/",{"scan_id":scan.id})
        self.assertEqual(created.status_code,201,created.get_json())
        report_id=created.get_json()["report"]["id"]
        download=self.client.get(f"/api/reports/{report_id}/download")
        self.assertEqual(download.status_code,200)
        self.assertTrue(download.data.startswith(b"%PDF"))
        download.close()
        other_client=app.test_client()
        self.login(other_client,email="b@example.test")
        self.assertEqual(other_client.get("/api/reports/").get_json(),[])
        self.assertEqual(other_client.get(f"/api/reports/{report_id}/download").status_code,404)
        self.assertEqual(self.mutate("delete",f"/api/reports/{report_id}",client=other_client).status_code,404)
        self.assertEqual(self.mutate("post","/api/reports/",{"scan_id":scan.id},client=other_client).status_code,404)
        self.assertEqual(self.mutate("delete",f"/api/reports/{report_id}").status_code,200)

    def test_background_job_lifecycle_and_owner_isolation(self):
        target=self.target()
        with patch("routes.scans.run_nmap_scan",return_value={"success":True,"raw_output":"443/tcp open https Test","open_ports":[{"port":"443","protocol":"tcp","service":"https","version":"Test"}]} ) as scanner:
            queued=self.mutate("post",f"/api/scans/nmap/{target.id}")
            self.assertEqual(queued.status_code,202)
            scanner.assert_not_called()
            job_id=queued.get_json()["job_id"]
            self.assertEqual(self.client.get(f"/api/scans/jobs/{job_id}").get_json()["status"],"queued")
            self.assertTrue(process_next_job(app))
            scanner.assert_called_once_with("127.0.0.1", 443)
        result=self.client.get(f"/api/scans/jobs/{job_id}").get_json()
        self.assertEqual(result["status"],"completed",result)
        self.assertEqual(Scan.query.one().status,"completed")
        other_client=app.test_client()
        self.login(other_client,email="b@example.test")
        self.assertEqual(other_client.get(f"/api/scans/jobs/{job_id}").status_code,404)
        self.assertEqual(self.mutate("delete",f"/api/targets/{target.id}").status_code,200)

    def test_web_options_are_encrypted_owner_scoped_and_cleared(self):
        target=self.target()
        options={'accounts':[{'headers':{'Authorization':'Bearer unique-test-secret'},'verify_path':'/me','verify_marker':'fixture-user'}]}
        queued=self.mutate('post',f'/api/scans/zap/{target.id}',options)
        self.assertEqual(queued.status_code,202,queued.get_json())
        job_id=queued.get_json()['job_id'];job=db.session.get(ScanJob,job_id)
        self.assertNotIn('unique-test-secret',job.encrypted_options)
        self.assertNotIn('encrypted_options',self.client.get(f'/api/scans/jobs/{job_id}').get_json())
        def scan(_url):
            from flask import g
            self.assertEqual(g.web_scan_options,options)
            return {'success':True,'raw_output':'{}','vulnerabilities':[]}
        with patch('routes.scans.run_zap_scan',side_effect=scan): process_next_job(app)
        db.session.expire_all()
        self.assertIsNone(db.session.get(ScanJob,job_id).encrypted_options)

    def test_web_partial_findings_survive_timeout_without_success(self):
        target=self.target()
        finding={'title':'Partial exposure','severity':'Medium','description':'Fixture','cve_id':'CWE-200'}
        queued=self.mutate('post',f'/api/scans/zap/{target.id}')
        with patch('routes.scans.run_zap_scan',return_value={'success':False,'error':'timed out','vulnerabilities':[finding],'raw_output':'partial'}):
            process_next_job(app)
        self.assertEqual(db.session.get(ScanJob,queued.get_json()['job_id']).status,'failed')
        self.assertEqual(Scan.query.one().status,'failed')
        self.assertEqual(Vulnerability.query.count(),1)

    def test_invalid_external_web_options_are_rejected(self):
        target=self.target()
        response=self.mutate('post',f'/api/scans/zap/{target.id}',{'openapi_path':'https://other.test/spec.json'})
        self.assertEqual(response.status_code,400)
        self.assertEqual(ScanJob.query.count(),0)

    def test_queued_cancel_is_owner_scoped_and_never_runs(self):
        target=self.target();queued=self.mutate('post',f'/api/scans/zap/{target.id}',{'paths':['/api/test']})
        ident=queued.get_json()['job_id']
        other=app.test_client();self.login(other,email='b@example.test')
        self.assertEqual(self.mutate('post',f'/api/scans/jobs/{ident}/cancel',client=other).status_code,404)
        self.assertEqual(self.mutate('post',f'/api/scans/jobs/{ident}/cancel').status_code,202)
        with patch('routes.scans.run_zap_scan') as scanner:
            self.assertFalse(process_next_job(app));scanner.assert_not_called()
        db.session.expire_all();job=db.session.get(ScanJob,ident)
        self.assertEqual(job.status,'cancelled');self.assertIsNone(job.encrypted_options)

    def test_running_cancel_stops_at_tool_boundary_and_clears_options(self):
        from sqlalchemy import text
        target=self.target();queued=self.mutate('post',f'/api/scans/full/{target.id}')
        ident=queued.get_json()['job_id']
        def first(_target):
            with db.engine.begin() as connection:
                connection.execute(text('UPDATE scan_jobs SET cancel_requested=1 WHERE id=:id'),{'id':ident})
            return {'status':'completed','found':0},0
        with patch('routes.scans._run_full_nmap',side_effect=first),patch('routes.scans.run_whatweb_scan') as scanner:
            process_next_job(app);scanner.assert_not_called()
        db.session.expire_all();job=db.session.get(ScanJob,ident)
        self.assertEqual(job.status,'cancelled');self.assertIsNone(job.encrypted_options)

    def test_progress_is_returned_without_secrets(self):
        target=self.target();queued=self.mutate('post',f'/api/scans/nmap/{target.id}')
        result=self.client.get('/api/scans/jobs/'+queued.get_json()['job_id']).get_json()
        self.assertEqual(result['stage'],'Queued');self.assertEqual(result['progress'],0)
        self.assertFalse(result['cancel_requested']);self.assertNotIn('encrypted_options',result)
        self.assertEqual(len(self.client.get('/api/scans/jobs').get_json()),1)
        other=app.test_client();self.login(other,email='b@example.test')
        self.assertEqual(other.get('/api/scans/jobs').get_json(),[])

    def test_full_scan_includes_tls_and_preserves_tool_failures(self):
        target=self.target()
        mocks={"nmap":{"success":True,"raw_output":"","open_ports":[]},
               "whatweb":{"success":True,"raw_output":"","technologies":[]},
               "zap":{"success":True,"raw_output":"","vulnerabilities":[]},
               "nuclei":{"success":False,"error":"test missing scanner"},
               "sslyze":{"success":True,"raw_output":"","vulnerabilities":[]}}
        from contextlib import ExitStack
        with ExitStack() as stack:
            for tool,result in mocks.items():
                stack.enter_context(patch(f"routes.scans.run_{tool}_scan",return_value=result))
            queued=self.mutate("post",f"/api/scans/full/{target.id}")
            self.assertEqual(queued.status_code,202)
            process_next_job(app)
        job=db.session.get(ScanJob,queued.get_json()["job_id"])
        payload=json.loads(job.result)
        self.assertEqual(set(payload["tools"]),set(mocks))
        self.assertEqual(payload["tools"]["nuclei"]["status"],"failed")
        self.assertEqual(payload["status"],"partial")
        self.assertEqual(payload["failed_tools"],["nuclei"])
        self.assertEqual(Scan.query.count(),5)

    def test_result_storage_failure_cannot_be_reported_as_completed(self):
        target=self.target()
        with patch("routes.scans.run_nmap_scan",return_value={"success":True,"raw_output":"","open_ports":[]}), patch(
            "routes.scans._save_findings",side_effect=RuntimeError("test storage failure")
        ):
            queued=self.mutate("post",f"/api/scans/nmap/{target.id}")
            process_next_job(app)
        self.assertEqual(db.session.get(ScanJob,queued.get_json()["job_id"]).status,"failed")
        self.assertEqual(Scan.query.one().status,"failed")

    def test_partial_findings_are_rolled_back_on_storage_failure(self):
        import routes.scans as scans_module
        target=self.target()
        original_save=scans_module._save_finding
        calls=[]
        def save_then_fail(scan,finding):
            calls.append(finding)
            if len(calls)==2:
                raise RuntimeError("test second finding failed")
            return original_save(scan,finding)
        result={"success":True,"raw_output":"test output","vulnerabilities":[
            {"title":"first","severity":"Low"},{"title":"second","severity":"Low"}]}
        with patch("routes.scans.run_nuclei_scan",return_value=result),patch("routes.scans._save_finding",side_effect=save_then_fail):
            queued=self.mutate("post",f"/api/scans/nuclei/{target.id}")
            process_next_job(app)
        self.assertEqual(len(calls),2)
        self.assertEqual(Vulnerability.query.count(),0)
        self.assertEqual(Scan.query.one().status,"failed")
        self.assertEqual(db.session.get(ScanJob,queued.get_json()["job_id"]).status,"failed")

    def test_worker_failure_recovery_and_queue_limits(self):
        target=self.target()
        with patch("routes.scans.run_nmap_scan",side_effect=RuntimeError("test parser failure")):
            queued=self.mutate("post",f"/api/scans/nmap/{target.id}")
            process_next_job(app)
        job=db.session.get(ScanJob,queued.get_json()["job_id"])
        self.assertEqual(job.status,"failed")
        self.assertEqual(Scan.query.one().status,"failed")
        job.status="running"
        db.session.commit()
        recover_interrupted_jobs(app)
        self.assertEqual(db.session.get(ScanJob,job.id).status,"failed")
        for _ in range(5):
            self.assertEqual(self.mutate("post",f"/api/scans/nmap/{target.id}").status_code,202)
        self.assertEqual(self.mutate("post",f"/api/scans/nmap/{target.id}").status_code,429)


if __name__ == "__main__":
    unittest.main()
