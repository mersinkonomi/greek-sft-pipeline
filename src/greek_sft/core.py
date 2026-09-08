from __future__ import annotations
import contextlib, datetime, fcntl, hashlib, json, os, shutil, tempfile
from pathlib import Path

VERSION = '1.0.0'
PIPELINE_ROOT = Path('/datadisk2/greekllm/GreekLLM_sft_pipeline')
STATUSES = {'accepted','rejected','quarantined','malformed','unsupported','license_blocked','processing_error'}

def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))

def digest(value):
    return hashlib.sha256(canonical_json(value).encode('utf-8')).hexdigest()

def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sha256_file(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(8 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def checked_output(path, root):
    root = Path(root).resolve(strict=True)
    result = Path(path).resolve(strict=False)
    if result != root and root not in result.parents:
        raise ValueError('Output path escapes the pipeline root')
    return result

def validate_roots(source, root):
    source, root = Path(source).resolve(strict=True), Path(root).resolve(strict=True)
    if not source.is_dir() or not root.is_dir() or source == root or source in root.parents or root in source.parents:
        raise ValueError('Unsafe source/output relationship')
    return source, root

def safe_output(path):
    path = Path(path).absolute()
    resolved = checked_output(path, PIPELINE_ROOT)
    current = path
    while current != current.parent:
        if current.is_symlink():
            raise ValueError('Symlink output component is forbidden')
        current = current.parent
    return resolved

def atomic_text(path, text):
    path = safe_output(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)

def atomic_json(path, value):
    atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n')

def read_jsonl(path):
    with Path(path).open(encoding='utf-8') as f:
        for line in f:
            if line.strip(): yield json.loads(line)

@contextlib.contextmanager
def run_lock(run_dir):
    path = safe_output(Path(run_dir) / '.run.lock')
    with path.open('a+') as f:
        try: fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('This run already has an active orchestrator')
        yield
        fcntl.flock(f, fcntl.LOCK_UN)

def freeze_config(root, run, config):
    fingerprint = digest(config)
    target = Path(run) / 'configuration.json'
    if target.exists():
        old = json.loads(target.read_text())
        if digest(old) != fingerprint: raise RuntimeError('Resume configuration changed; use a new run')
    else: atomic_json(target, config)
    return fingerprint

def checkpoint_complete(root, checkpoint, stats, config):
    root, checkpoint = Path(root), safe_output(checkpoint)
    checkpoint.mkdir(parents=True, exist_ok=True)
    atomic_json(checkpoint / 'statistics.json', stats)
    atomic_json(checkpoint / 'configuration.json', config)
    errors = checkpoint / 'errors.jsonl'
    if not errors.exists(): atomic_text(errors, '')
    snapshot = checkpoint / 'configuration_snapshot'
    snapshot.mkdir(exist_ok=True)
    for relative in ('configs', 'schemas', 'prompts', 'src', 'scripts'):
        parent = root / relative
        if parent.exists():
            for source in sorted(parent.rglob('*')):
                if source.is_file() and '__pycache__' not in source.parts:
                    target = safe_output(snapshot / source.relative_to(root))
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if not target.exists(): shutil.copyfile(source, target)
    artifacts = []
    for path in sorted(checkpoint.rglob('*')):
        if path.is_file() and path.name not in ('checkpoint_manifest.json', 'checksums.sha256') and not path.name.endswith(('-wal','-shm','_heartbeat.json')) and path.name!='progress.json':
            artifacts.append({'path': str(path.relative_to(checkpoint)), 'bytes': path.stat().st_size, 'sha256': sha256_file(path)})
    manifest = {'version': VERSION, 'completed_at': utcnow(), 'configuration_hash': digest(config), 'artifacts': artifacts, 'excluded_advisory_telemetry':['progress.json','*_heartbeat.json']}
    atomic_json(checkpoint / 'checkpoint_manifest.json', manifest)
    artifacts.append({'path':'checkpoint_manifest.json', 'sha256':sha256_file(checkpoint / 'checkpoint_manifest.json')})
    atomic_text(checkpoint / 'checksums.sha256', ''.join(x['sha256'] + '  ' + x['path'] + '\n' for x in artifacts))
    return manifest

def check_checkpoint(checkpoint, config):
    path = Path(checkpoint) / 'checkpoint_manifest.json'
    if not path.exists(): return False
    manifest = json.loads(path.read_text())
    if manifest['configuration_hash'] != digest(config): raise RuntimeError('Checkpoint configuration mismatch')
    for item in manifest['artifacts']:
        target = Path(checkpoint) / item['path']
        if not target.is_file() or sha256_file(target) != item['sha256']:
            raise RuntimeError('Checkpoint artifact changed: ' + item['path'])
    return True


def capture_execution_attempt(root, run):
    """Preserve exact code/config/test inputs for each new orchestrator process."""
    import uuid, zipfile
    root=Path(root)
    attempt=safe_output(Path(run)/'execution_attempts'/uuid.uuid4().hex)
    attempt.mkdir(parents=True,exist_ok=False)
    paths=[]
    for name in ('configs','schemas','prompts','src','scripts','tests','.codex'):
        parent=root/name
        if parent.exists():
            for path in sorted(parent.rglob('*')):
                if path.is_file() and '__pycache__' not in path.parts and not (name=='tests' and 'runtime' in path.relative_to(parent).parts):
                    paths.append(path)
    for name in ('AGENTS.md','README.md','.gitignore','.env.example'):
        if (root/name).is_file(): paths.append(root/name)
    artifacts=[]
    archive=safe_output(attempt/'code_configuration_tests.zip')
    with archive.open('xb') as stream:
        with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for path in sorted(paths):
                if path.is_symlink(): raise ValueError('Execution snapshot input symlink forbidden')
                relative=str(path.relative_to(root)); raw=path.read_bytes()
                z.writestr(relative,raw)
                artifacts.append({'path':relative,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
        stream.flush(); os.fsync(stream.fileno())
    manifest={'captured_at':utcnow(),'archive_sha256':sha256_file(archive),'artifacts':artifacts,
        'scope':'Code, configurations, prompts, schemas, tests and orchestration; environment secrets excluded.'}
    atomic_json(attempt/'manifest.json',manifest)
    return str(attempt.relative_to(run))
