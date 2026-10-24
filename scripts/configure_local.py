"""Generate private configuration without overwriting an existing installation."""
import argparse
from pathlib import Path
import secrets


def configure(root, docker=False):
    template=root/('.env.example' if docker else 'backend/.env.example')
    destination=root/('.env' if docker else 'backend/.env')
    replacements=({'SENTINELX_DB_ROOT_PASSWORD','SENTINELX_DB_PASSWORD','SENTINELX_SECRET_KEY','SENTINELX_ZAP_API_KEY'}
                  if docker else {'SECRET_KEY','ZAP_API_KEY'})
    lines=[]
    for line in template.read_text(encoding='utf-8').splitlines():
        name=line.partition('=')[0]
        lines.append(name+'='+secrets.token_hex(32) if name in replacements else line)
    # Exclusive creation: never replace existing credentials.
    with destination.open('x',encoding='utf-8') as stream:
        stream.write('\n'.join(lines)+'\n')
    try:
        destination.chmod(0o600)
    except OSError:
        pass
    return destination


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker',action='store_true')
    args=parser.parse_args()
    try:
        result=configure(Path(__file__).resolve().parent.parent,args.docker)
    except FileExistsError:
        parser.exit(1,'Configuration already exists; nothing was overwritten.\n')
    print('Private configuration created:',result)
    print('Keep it out of Git. Configure database/scanner settings before starting.')
