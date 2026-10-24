"""Windows local frontend/backend supervisor. Never terminates a listening process."""
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import time
from urllib.request import urlopen

PROJECT = Path(__file__).resolve().parent.parent
LOCAL = PROJECT / '.local'
BACKEND_PORT = 5000
FRONTEND_PORT = 8088


def backend_state():
    try:
        with urlopen(f'http://127.0.0.1:{BACKEND_PORT}/', timeout=3) as response:
            value = json.loads(response.read(4096))
        if value.get('status') == 'OK' and value.get('message') == 'SentinelX Backend is running successfully.':
            return 'healthy'
    except (OSError, ValueError, AttributeError):
        pass
    try:
        with socket.create_connection(('127.0.0.1', BACKEND_PORT), timeout=1):
            return 'occupied'
    except OSError:
        return 'stopped'


def check_backend(start_backend):
    state = backend_state()
    if state == 'stopped':
        start_backend()
        return 'restarted'
    return state


def frontend_state():
    try:
        with urlopen(f'http://127.0.0.1:{FRONTEND_PORT}/login', timeout=3) as response:
            page = response.read(128 * 1024).decode('utf-8', errors='replace')
        if '<title>SentinelX | Security Workspace</title>' in page and 'id="root"' in page:
            return 'healthy'
    except (OSError, ValueError):
        pass
    try:
        with socket.create_connection(('127.0.0.1', FRONTEND_PORT), timeout=1):
            return 'occupied'
    except OSError:
        return 'stopped'


def check_services(start_backend, start_frontend):
    backend = check_backend(start_backend)
    frontend = frontend_state()
    if frontend == 'stopped':
        start_frontend()
        frontend = 'restarted'
    return {'backend': backend, 'frontend': frontend}


def supervise():
    if os.name != 'nt':
        raise RuntimeError('The local supervisor is supported on Windows only.')
    import msvcrt
    LOCAL.mkdir(exist_ok=True)
    with (LOCAL / 'supervisor.lock').open('a+b') as lock:
        lock.seek(0, 2)
        if lock.tell() == 0:
            lock.write(b'0'); lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return
        logger = logging.getLogger('sentinelx.supervisor')
        logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(LOCAL / 'supervisor.log', maxBytes=1024*1024, backupCount=2)
        handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        logger.addHandler(handler)
        def start_backend():
            with (LOCAL / 'backend.log').open('ab') as output:
                subprocess.Popen([sys.executable, '-B', str(PROJECT / 'backend/app.py')],
                    cwd=PROJECT / 'backend', stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                    creationflags=subprocess.CREATE_NO_WINDOW, close_fds=True)
        def start_frontend():
            node = shutil.which('node') or str(Path(os.environ.get('PROGRAMFILES', r'C:\Program Files')) / 'nodejs/node.exe')
            vite = PROJECT / 'frontend/node_modules/vite/bin/vite.js'
            if not vite.is_file():
                raise RuntimeError('Frontend dependencies are missing. Run the installer or npm ci first.')
            with (LOCAL / 'frontend.log').open('ab') as output:
                subprocess.Popen([node, str(vite), 'preview', '--host', '127.0.0.1', '--port', str(FRONTEND_PORT), '--strictPort'],
                    cwd=PROJECT / 'frontend', stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                    creationflags=subprocess.CREATE_NO_WINDOW, close_fds=True)
        delay = 10
        try:
            logger.info('Local frontend/backend supervision started.')
            while not (LOCAL / 'stop-supervisor').exists():
                try:
                    states = check_services(start_backend, start_frontend)
                    for service, state in states.items():
                        if state == 'restarted':
                            logger.warning('%s port was closed; started a replacement. Interrupted scans are not silently resumed.', service)
                        elif state == 'occupied':
                            logger.warning('%s port is occupied but service identity is unconfirmed. No process was stopped.', service)
                    delay = min(60, delay * 2) if 'restarted' in states.values() else 10
                except Exception:
                    logger.exception('Backend supervision check failed.')
                    delay = min(60, delay * 2)
                time.sleep(delay)
            logger.info('Supervision stopped by local stop-supervisor flag.')
        finally:
            lock.seek(0); msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            handler.close(); logger.removeHandler(handler)


if __name__ == '__main__':
    supervise()
