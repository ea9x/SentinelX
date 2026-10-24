"""Bounded TCP/TLS/HTTP HEAD checks; no credentials or redirects."""
import socket
import ssl
import re


def _http_status(connection):
    # TCP can split the status line across packets. Never read an unbounded body.
    data = b''
    while len(data) < 256 and b'\n' not in data:
        chunk = connection.recv(256-len(data))
        if not chunk: break
        data += chunk
    return bool(re.match(rb'^HTTP/1\.[01] [1-5][0-9]{2}(?: |\r|\n)', data))

def inspect_target(host, port):
    result={'host':host,'port':int(port),'tcp_open':False,'tls':False,'http':False,'service':'unknown','certificate_validated':False}
    authority = ('['+host+']' if ':' in host else host)+':'+str(int(port))
    head = f'HEAD / HTTP/1.0\r\nHost: {authority}\r\nConnection: close\r\n\r\n'.encode('ascii')
    try:
        with socket.create_connection((host,int(port)),timeout=3): pass
        result['tcp_open']=True
    except (OSError,ValueError):
        return {**result,'message':'The target port is unavailable. Check the address, service and firewall.'}
    try:
        # Detect protocol support only. This is not certificate validation.
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
        with socket.create_connection((host,int(port)),timeout=3) as raw:
            with context.wrap_socket(raw,server_hostname=host) as secure:
                result['tls']=True
                secure.sendall(head)
                result['http']=_http_status(secure)
    except (OSError,ValueError): pass
    if not result['tls']:
        try:
            with socket.create_connection((host,int(port)),timeout=3) as raw:
                raw.sendall(head)
                result['http']=_http_status(raw)
        except (OSError,ValueError): pass
    result['service']='https' if result['tls'] and result['http'] else 'tls' if result['tls'] else 'http' if result['http'] else 'unknown'
    result['message']='Target service is reachable.' if result['http'] else 'The port is open, but a web service was not confirmed.'
    result['certificate_validated']=False
    return result
