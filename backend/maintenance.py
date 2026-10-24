"""Local startup and encrypted backups. Restore verification never touches MySQL."""
import argparse
import base64
from datetime import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid
import zipfile
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, select, text

PROJECT=Path(__file__).resolve().parent.parent
LOCAL=PROJECT/'.local'
RESTORE=Path(os.environ.get('LOCALAPPDATA',str(LOCAL)))/'SentinelX/restore-checks'


def _encode(value):
    if isinstance(value,datetime): return {'__datetime__':value.isoformat()}
    if isinstance(value,bytes): return {'__bytes__':base64.b64encode(value).decode()}
    raise TypeError('Unsupported backup value.')


def _decode(value):
    if set(value)=={'__datetime__'}: return datetime.fromisoformat(value['__datetime__'])
    if set(value)=={'__bytes__'}: return base64.b64decode(value['__bytes__'])
    return value


def _key():
    folder=Path(os.environ['LOCALAPPDATA'])/'SentinelX'
    folder.mkdir(parents=True,exist_ok=True)
    path=folder/'backup.key'
    if not path.exists():
        with path.open('xb') as stream: stream.write(Fernet.generate_key())
    return Fernet(path.read_bytes())


def backup():
    from app import app
    from models import db
    LOCAL.mkdir(exist_ok=True);folder=LOCAL/'backups';folder.mkdir(exist_ok=True)
    with app.app_context(), db.engine.connect() as connection:
        if connection.execute(text("SELECT COUNT(*) FROM scan_jobs WHERE status IN ('queued','running')")).scalar():
            raise RuntimeError('Backup deferred until the scan queue is idle.')
        connection.rollback()
        if connection.dialect.name in {'mysql','mariadb'}:
            connection.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ'))
            connection.execute(text('START TRANSACTION WITH CONSISTENT SNAPSHOT'))
        tables={table.name:[dict(row) for row in connection.execute(select(table).order_by(*table.primary_key.columns)).mappings()]
                for table in db.metadata.sorted_tables}
        payload=json.dumps({'format':1,'tables':tables},default=_encode,sort_keys=True).encode()
        connection.rollback()
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('database.json',payload)
        total=len(payload)
        candidates=[PROJECT/'backend/.env',PROJECT/'compose.yaml',PROJECT/'frontend/package.json',PROJECT/'backend/requirements.txt']
        for directory in ['backend/uploads','backend/generated_reports']:
            if (PROJECT/directory).exists(): candidates.extend((PROJECT/directory).rglob('*'))
        for path in candidates:
            if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(PROJECT.resolve()): continue
            total+=path.stat().st_size
            if total>100*1024*1024: raise RuntimeError('Backup exceeds the 100 MiB local archive limit.')
            archive.write(path,path.relative_to(PROJECT).as_posix())
    result=folder/(datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:6]+'.sxbackup')
    with result.open('xb') as stream: stream.write(_key().encrypt(buffer.getvalue()))
    verified=verify(result)
    return {'archive':str(result),'verified_restore':verified,'key_location':str(Path(os.environ['LOCALAPPDATA'])/'SentinelX/backup.key')}


def verify(path):
    from models import db
    payload=_key().decrypt(Path(path).read_bytes())
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        raw=archive.read('database.json')
    snapshot=json.loads(raw,object_hook=_decode)
    if snapshot.get('format')!=1: raise ValueError('Unsupported backup format.')
    if not isinstance(snapshot.get('tables'),dict): raise ValueError('Invalid backup table data.')
    unknown=set(snapshot['tables'])-set(db.metadata.tables)
    if unknown: raise ValueError('Backup contains tables unsupported by this version.')
    RESTORE.mkdir(parents=True,exist_ok=True)
    destination=(RESTORE/('restore-check-'+uuid.uuid4().hex+'.sqlite')).resolve()
    assert destination.is_relative_to(RESTORE.resolve()) and not destination.exists()
    engine=create_engine('sqlite:///'+destination.as_posix())
    try:
        db.metadata.create_all(engine)
        with engine.begin() as connection:
            connection.execute(text('PRAGMA foreign_keys=ON'))
            for table in db.metadata.sorted_tables:
                rows=snapshot['tables'].get(table.name,[])
                if rows: connection.execute(table.insert(),rows)
            restored={table.name:[dict(row) for row in connection.execute(select(table).order_by(*table.primary_key.columns)).mappings()]
                      for table in db.metadata.sorted_tables}
        # Older archives predate additive tables; they restore as empty tables.
        expected={table.name:snapshot['tables'].get(table.name,[]) for table in db.metadata.sorted_tables}
        original=json.dumps(expected,default=_encode,sort_keys=True).encode()
        actual=json.dumps(restored,default=_encode,sort_keys=True).encode()
        if original!=actual: raise RuntimeError('Restored data does not match the backup.')
        return {'tables':len(restored),'rows':sum(map(len,restored.values())),'sha256':hashlib.sha256(actual).hexdigest(),
                'method':'Fresh isolated SQLite restore; MySQL service was not modified.'}
    finally:
        engine.dispose()
        if destination.exists(): destination.unlink()


def _listening(port):
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=1): return True
    except OSError: return False


def _start_services():
    from dotenv import load_dotenv
    load_dotenv(PROJECT/'backend/.env')
    LOCAL.mkdir(exist_ok=True)
    def launch(args,folder,log):
        output=(LOCAL/log).open('ab')
        try: subprocess.Popen(args,cwd=folder,stdin=subprocess.DEVNULL,stdout=output,stderr=output,
                              creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),close_fds=True)
        finally: output.close()
    if not _listening(8080):
        zap=Path(os.environ.get('PROGRAMFILES',r'C:\Program Files'))/'ZAP/Zed Attack Proxy/ZAP.exe'
        if zap.exists() and os.getenv('ZAP_API_KEY'): launch([str(zap),'-daemon','-host','127.0.0.1','-port','8080','-config','api.key='+os.getenv('ZAP_API_KEY','')],zap.parent,'zap.log')
    if not _listening(5000):
        for _ in range(30):
            if _listening(3306): break
            time.sleep(2)
        else: raise RuntimeError('MySQL is unavailable. Start its Windows service and try again.')
        launch([str(PROJECT/'backend/venv/Scripts/python.exe'),'-B','app.py'],PROJECT/'backend','backend.log')
    if not _listening(8088):
        node=Path(os.environ.get('PROGRAMFILES',r'C:\Program Files'))/'nodejs/node.exe'
        launch([str(node),str(PROJECT/'frontend/node_modules/vite/bin/vite.js'),'preview','--host','127.0.0.1','--port','8088','--strictPort'],PROJECT/'frontend','frontend.log')
    if not _listening(5173):
        launch([str(PROJECT/'backend/venv/Scripts/python.exe'),'-B','legacy_redirect.py'],PROJECT/'backend','legacy-redirect.log')
    for _ in range(30):
        if _listening(5000) and _listening(8088): break
        time.sleep(.5)
    else: raise RuntimeError('Local services did not become ready. See .local service logs.')
    if os.name == 'nt':
        (LOCAL/'stop-supervisor').unlink(missing_ok=True)
        launch([sys.executable,'-B',str(PROJECT/'backend/local_supervisor.py')],PROJECT/'backend','supervisor-launch.log')
    existing=list((LOCAL/'backups').glob('*.sxbackup')) if (LOCAL/'backups').exists() else []
    result={'message':'Local services started or already listening. Open http://127.0.0.1:8088/login.'}
    from app import app, system_health
    with app.test_request_context('/api/health'):
        response,_status=system_health.__wrapped__()
        result['services']=response.get_json()

    if not existing or time.time()-max(p.stat().st_mtime for p in existing)>86400:
        try:
            from app import app
            with app.app_context(): result['backup']=backup()
        except Exception:
            result['backup']='Deferred or failed. Run the backup command after the database and scan queue are ready.'
    return result


def start():
    import msvcrt
    LOCAL.mkdir(exist_ok=True)
    with (LOCAL/'startup.lock').open('a+b') as lock:
        lock.seek(0,2)
        if lock.tell()==0: lock.write(b'0');lock.flush()
        lock.seek(0)
        try: msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
        except OSError: return {'message':'Another SentinelX startup is already in progress.'}
        try: return _start_services()
        finally:
            lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['start','backup','verify'])
    parser.add_argument('archive',nargs='?');args=parser.parse_args()
    if args.action=='start': result=start()
    else:
        from app import app
        with app.app_context(): result=backup() if args.action=='backup' else verify(args.archive)
    print(json.dumps(result,indent=2))
