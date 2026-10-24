"""Reject private/generated files in the Git publication set. Not a full secret scanner."""
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parent.parent
BAD_PARTS={'.local','.docker-local','node_modules','venv','.venv','__pycache__','generated_reports','uploads','tools','dist'}
BAD_SUFFIXES={'.key','.pem','.p12','.pfx','.sqlite','.sqlite3','.db','.sql','.sxbackup','.log','.pid','.exe','.dll','.msi','.7z','.zip','.pdf'}

def candidates(root):
    if (root/'.git').exists():
        result=subprocess.run(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=root,capture_output=True,check=True)
        return sorted(set(result.stdout.decode().split('\0'))-{''})
    return sorted(p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and '.git' not in p.relative_to(root).parts)

def check(root):
    issues=[];files=candidates(root)
    for name in files:
        relative=Path(name);path=root/relative
        if not path.is_file():
            continue
        if path.is_symlink():issues.append((name,'symlink is not allowed in source package'));continue
        if (any(part in BAD_PARTS or part.lower().startswith('backup') for part in relative.parts)
            or relative.suffix.lower() in BAD_SUFFIXES
            or (relative.name.startswith('.env') and relative.name!='.env.example')):
            issues.append((name,'private, external runtime or generated artifact'));continue
        if path.stat().st_size>5*1024*1024:issues.append((name,'file exceeds 5 MiB source limit'))
        try:text=path.read_text(encoding='utf-8-sig')
        except (UnicodeError,OSError):continue
        if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',text):issues.append((name,'private key content'))
        if re.search(r'gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}',text):issues.append((name,'credential-shaped token'))
        if re.search(r'[A-Za-z]:[\\/]Users[\\/](?!Public[\\/])[^\\/\s]+',text):issues.append((name,'personal absolute home path'))
        if relative.name=='.env.example':
            for line in text.splitlines():
                key,sep,value=line.partition('=')
                if sep and any(word in key.upper() for word in ['PASSWORD','SECRET','API_KEY']) and value.strip():
                    issues.append((name,'example secret must be blank'))
    for required in ['README.md','.gitignore','SECURITY.md','backend/.env.example','.env.example','frontend/package-lock.json']:
        if required not in files:issues.append((required,'required source file missing'))
    return files,issues

if __name__=='__main__':
    files,issues=check(ROOT)
    print(json.dumps({'files_checked':len(files),'issues':[{'path':p,'reason':r} for p,r in issues]},indent=2))
    sys.exit(1 if issues else 0)
