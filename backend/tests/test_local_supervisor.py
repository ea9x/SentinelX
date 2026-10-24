import unittest
from unittest.mock import patch, Mock
import local_supervisor as supervisor

class SupervisorTests(unittest.TestCase):
    def test_closed_backend_starts_once_and_occupied_ports_are_never_replaced(self):
        for state in ['healthy','occupied','stopped']:
            with self.subTest(state=state), patch.object(supervisor,'backend_state',return_value=state):
                start=Mock()
                self.assertEqual(supervisor.check_backend(start),'restarted' if state=='stopped' else state)
                self.assertEqual(start.call_count,1 if state=='stopped' else 0)

    def test_identity_and_port_state(self):
        for payload in [b'{"status":"OK","message":"Unrelated application"}',b'invalid json']:
            with self.subTest(payload=payload),patch.object(supervisor,'urlopen') as fetch,patch.object(supervisor.socket,'create_connection'):
                fetch.return_value.__enter__.return_value.read.return_value=payload
                self.assertEqual(supervisor.backend_state(),'occupied')
        with patch.object(supervisor,'urlopen',side_effect=OSError),patch.object(supervisor.socket,'create_connection',side_effect=OSError):
            self.assertEqual(supervisor.backend_state(),'stopped')
        with patch.object(supervisor,'urlopen') as fetch,patch.object(supervisor.socket,'create_connection') as connect:
            fetch.return_value.__enter__.return_value.read.return_value=b'{"status":"OK","message":"SentinelX Backend is running successfully."}'
            self.assertEqual(supervisor.backend_state(),'healthy');connect.assert_not_called()

    def test_frontend_identity_requires_application_markup(self):
        for page,expected in [(b'<title>Unrelated</title><div id="root"></div>','occupied'),
                              (b'<title>SentinelX | Security Workspace</title><div id="root"></div>','healthy')]:
            with self.subTest(page=page),patch.object(supervisor,'urlopen') as fetch,patch.object(supervisor.socket,'create_connection'):
                fetch.return_value.__enter__.return_value.read.return_value=page
                self.assertEqual(supervisor.frontend_state(),expected)
        with patch.object(supervisor,'urlopen',side_effect=OSError),patch.object(supervisor.socket,'create_connection',side_effect=OSError):
            self.assertEqual(supervisor.frontend_state(),'stopped')

    def test_frontend_failure_restarts_only_frontend_and_never_an_occupied_port(self):
        for state in ['healthy','occupied','stopped']:
            with self.subTest(state=state),patch.object(supervisor,'backend_state',return_value='healthy'),patch.object(supervisor,'frontend_state',return_value=state):
                backend=Mock();frontend=Mock();result=supervisor.check_services(backend,frontend)
                backend.assert_not_called()
                self.assertEqual(frontend.call_count,1 if state=='stopped' else 0)
                self.assertEqual(result['frontend'],'restarted' if state=='stopped' else state)
