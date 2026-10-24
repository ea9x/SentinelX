"""Guided Windows setup. Private configuration is never overwritten."""
import argparse
import getpass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import venv
from configure_local import configure

ROOT=Path(__file__).resolve().parent.parent
DATABASE_KEYS=('DATABASE_URL','DB_HOST','DB_USER','DB_PASSWORD','DB_NAME','SECRET_KEY','PUBLIC_APP_URL','ZAP_API_KEY')


def prerequisites():
    problems=[]
    if sys.version_info[:2] != (3,12):
        problems.append('Run this installer with Python 3.12: py -3.12 scripts/setup_windows.py')
    node=shutil.which('node');npm=shutil.which('npm.cmd' if os.name=='nt' else 'npm')
    if not node or not npm:
        problems.append('Install Node.js 24, including npm, and reopen the installer.')
    else:
        try:
            version=subprocess.check_output([node,'--version'],text=True,timeout=10).strip()
            if version.split('.')[0]!='v24':problems.append('Node.js 24 is the tested runtime. Detected '+version)
        except (OSError,subprocess.SubprocessError):problems.append('Node.js could not be executed.')
    return node,npm,problems


def create_configuration(root,mode,mysql=None):
    if (root/'backend/.env').exists():return False
    if mode=='sqlite':
        folder=root/'.local';folder.mkdir(exist_ok=True)
        settings={'DATABASE_URL':'sqlite:///'+(folder/'sentinelx.sqlite').resolve().as_posix()}
    elif mode=='mysql':
        settings=dict(mysql or {})
        if set(settings)!=set(('DB_HOST','DB_NAME','DB_USER','DB_PASSWORD')) or not all(settings.values()):
            raise ValueError('Provide a dedicated MySQL host, database, user and password.')
    else:raise ValueError('Choose sqlite or mysql.')
    # Collect/validate settings first. Exclusive creation never replaces an existing file.
    destination=configure(root)
    with destination.open('a',encoding='utf-8') as stream:
        stream.write('\n# Installation choices\n')
        for key,value in settings.items():stream.write(key+'='+json.dumps(value,ensure_ascii=False)+'\n')
    return True


def child_environment():
    environment=os.environ.copy()
    # Database/bootstrap commands must use this installation's .env, not unrelated shell settings.
    for key in DATABASE_KEYS:environment.pop(key,None)
    return environment


def database_check(python,root):
    code='''import sys
try:
 from app import app
 from schema import ensure_schema
 from models import User
 with app.app_context():
  ensure_schema()
  print('HAS_ACCOUNTS' if User.query.first() else 'NEEDS_ADMIN')
except Exception:
 print('Database setup failed. Check your private backend/.env and database availability.',file=sys.stderr)
 sys.exit(2)
'''
    result=subprocess.run([str(python),'-B','-c',code],cwd=root/'backend',env=child_environment(),capture_output=True,text=True)
    if result.returncode:raise RuntimeError('Database setup failed. Check backend/.env and the dedicated database; existing configuration was retained.')
    return 'HAS_ACCOUNTS' in result.stdout


def scanner_paths():
    return {name:bool(shutil.which(executable)) for name,executable in [('Nmap','nmap'),('Nuclei','nuclei'),('Ruby','ruby'),('SSLyze','sslyze')]}


def run(args,root):
    if os.name!='nt':raise RuntimeError('This installer targets Windows. See README for other environments.')
    node,npm,problems=prerequisites()
    if problems:raise RuntimeError('\n'.join(problems))
    print('Python 3.12 and Node.js 24 are available.')
    if args.check_only:
        print('Preflight complete. No environment, dependencies, accounts or services were changed.')
        return
    existing=(root/'backend/.env').exists()
    mode=args.mode
    mysql=None
    if not existing:
        if not mode:
            if args.non_interactive:raise RuntimeError('--mode is required for unattended setup.')
            choice=input('Database: [1] SQLite local trial (default), [2] existing dedicated MySQL: ').strip()
            if choice not in ('','1','2'):raise RuntimeError('Choose 1 or 2.')
            mode='mysql' if choice=='2' else 'sqlite'
        if mode=='mysql':
            if args.non_interactive:raise RuntimeError('Configure backend/.env before unattended MySQL setup; passwords are never accepted in command arguments.')
            print('Create your dedicated MySQL database/user first; this installer does not request root privileges.')
            mysql={'DB_HOST':input('Database host [127.0.0.1]: ').strip() or '127.0.0.1',
                   'DB_NAME':input('Database name: ').strip(),'DB_USER':input('Database user: ').strip(),
                   'DB_PASSWORD':getpass.getpass('Database password (hidden): ')}
        create_configuration(root,mode,mysql)
    else:print('Existing backend/.env retained, including database selection and signing keys.')
    python=root/'backend/venv/Scripts/python.exe'
    if not python.exists():
        print('Creating the application Python environment...')
        venv.EnvBuilder(with_pip=True).create(root/'backend/venv')
    print('Installing application dependencies...')
    subprocess.run([str(python),'-m','pip','install','-r',str(root/'backend/requirements-lock.txt')],cwd=root,check=True)
    subprocess.run([str(python),'-m','pip','check'],cwd=root,check=True)
    print('Installing and building the frontend...')
    subprocess.run([npm,'ci'],cwd=root/'frontend',check=True)
    subprocess.run([npm,'run','build'],cwd=root/'frontend',check=True)
    accounts=database_check(python,root)
    if not accounts and not args.non_interactive:
        print('Create your first administrator; no default account is shipped.')
        subprocess.run([str(python),'-m','flask','--app','app','create-initial-admin'],cwd=root/'backend',env=child_environment(),check=True)
        accounts=database_check(python,root)
    print('Scanner PATH discovery (configured executable paths may differ):',json.dumps(scanner_paths()))
    print('Install missing scanner tools separately. See INSTALL-WINDOWS.md; ZAP needs its own matching API key. Missing tools are not successful scans.')
    if not accounts:
        print('Application installed; initial administrator is still required. Run the create-initial-admin command from README before signing in.')
    else:print('Application setup complete. Existing accounts and configuration were retained where present.')
    if args.start:
        if not accounts:raise RuntimeError('Start deferred until an initial administrator is created.')
        subprocess.run(['powershell.exe','-NoProfile','-File',str(root/'start_local.ps1'),'-Quiet'],cwd=root,env=child_environment(),check=True)
        print('Open http://127.0.0.1:8088/login')
    else:print('Start services with start_local.ps1 after setup. They were not started automatically.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only',action='store_true')
    parser.add_argument('--mode',choices=['sqlite','mysql'])
    parser.add_argument('--non-interactive',action='store_true',help='Install without prompts; never creates an administrator.')
    parser.add_argument('--start',action='store_true')
    options=parser.parse_args()
    try:run(options,ROOT)
    except (RuntimeError,ValueError,OSError,subprocess.SubprocessError) as error:
        # Never print child database exceptions or private configuration contents.
        print('Setup did not finish:',str(error),file=sys.stderr)
        sys.exit(1)
