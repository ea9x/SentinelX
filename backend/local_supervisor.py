"""Windows local backend supervisor. Never terminates a listening process."""
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.request import urlopen

PROJECT = Path(__file__).resolve().parent.parent
LOCAL = PROJECT / '.local'
BACKEND_PORT = 5000


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
        delay = 10
        try:
            logger.info('Local backend supervision started.')
            while not (LOCAL / 'stop-supervisor').exists():
                try:
                    state = check_backend(start_backend)
                    if state == 'restarted':
                        logger.warning('Backend port was closed; started a new backend. Interrupted scans are recovered as failed, never silently resumed.')
                        delay = min(60, delay * 2)
                    elif state == 'healthy':
                        delay = 10
                    else:
                        logger.warning('Port 5000 is occupied but backend identity is unconfirmed. No process was stopped.')
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
