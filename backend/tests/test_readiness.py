"""Protocol detection tests use controlled sockets and never probe user targets."""
import unittest
from unittest.mock import MagicMock,patch
from readiness import inspect_target,_http_status


class ReadinessTests(unittest.TestCase):
    def test_fragmented_http_status_and_invalid_banner(self):
        connection=MagicMock();connection.recv.side_effect=[b'HT',b'TP/1.1 302 Found\r\n']
        self.assertTrue(_http_status(connection))
        connection.recv.side_effect=[b'HTTP/not a status\n']
        self.assertFalse(_http_status(connection))
        connection.recv.side_effect=[b'x'*256]
        self.assertFalse(_http_status(connection));connection.recv.assert_called_with(256)

    def test_closed_port_retains_explicit_certificate_state(self):
        with patch('readiness.socket.create_connection',side_effect=OSError('closed')):
            result=inspect_target('127.0.0.1',8443)
        self.assertFalse(result['tcp_open']);self.assertFalse(result['certificate_validated'])

    def test_plain_http_on_tls_default_port_preserves_ipv6_host_and_port(self):
        connection=MagicMock();connection.__enter__.return_value=connection
        connection.recv.return_value=b'HTTP/1.1 401 Unauthorized\r\n'
        context=MagicMock();context.wrap_socket.side_effect=OSError('not TLS')
        with patch('readiness.socket.create_connection',return_value=connection),patch('readiness.ssl.SSLContext',return_value=context):
            result=inspect_target('::1',443)
        self.assertEqual(result['service'],'http');self.assertFalse(result['tls'])
        connection.sendall.assert_called_once_with(b'HEAD / HTTP/1.0\r\nHost: [::1]:443\r\nConnection: close\r\n\r\n')

    def test_https_on_nonstandard_port_does_not_check_certificate_validity(self):
        raw=MagicMock();raw.__enter__.return_value=raw
        secure=MagicMock();secure.__enter__.return_value=secure
        secure.recv.return_value=b'HTTP/1.0 403 Forbidden\r\n'
        context=MagicMock();context.wrap_socket.return_value=secure
        with patch('readiness.socket.create_connection',return_value=raw),patch('readiness.ssl.SSLContext',return_value=context):
            result=inspect_target('example.test',8443)
        self.assertEqual(result['service'],'https');self.assertFalse(result['certificate_validated'])
        secure.sendall.assert_called_once_with(b'HEAD / HTTP/1.0\r\nHost: example.test:8443\r\nConnection: close\r\n\r\n')
