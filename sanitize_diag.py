#!/usr/bin/env python3
"""Offline Splunk archive orchestration; all replacements delegated to LogTotal."""
import argparse, collections, gzip, io, ipaddress, json, os, re, shutil, subprocess, tarfile, tempfile, time, sys, threading
from pathlib import Path, PurePosixPath

DEFAULT_EXTENSIONS = ['.log', '.conf']

RULES = ['secrets','sessionCookies','ips','hosts','users','paths']
DENY = {'splunk.secret','passwd','passwords.conf','authentication.conf','user-seed.conf','server.pem','privkey.pem'}
SUFFIX = {'.pem','.key','.crt','.cer','.der','.p12','.pfx','.jks','.db','.sqlite','.zip','.tgz','.tar','.gz','.bz2','.xz','.7z','.zst','.dump','.dmp','.core','.kdb','.p7b','.p7c','.keystore','.truststore'}

class Progress:
    """Periodic status on stderr; never emit input paths or raw values."""
    def __init__(self, interval=10, quiet=False):
        self.interval = interval
        self.quiet = quiet
        self.start = time.monotonic()
        self.last = self.start
        self.stage = 'Initializing'
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.worker = None
        self.tty = sys.stderr.isatty()
        self.drawn = False
        self.last_draw = 0.0

    def emit(self, message):
        if not self.quiet:
            with self.lock:
                line = f'[{time.monotonic()-self.start:7.1f}s] {message}'
                if self.tty:
                    width = shutil.get_terminal_size((100, 24)).columns
                    sys.stderr.write('\r\x1b[2K' + line[:max(1, width-1)])
                    sys.stderr.flush()
                    self.drawn = True
                    self.last_draw = time.monotonic()
                else:
                    print(line, file=sys.stderr, flush=True)

    def update(self, stage, announce=False):
        with self.lock:
            self.stage = stage
        if announce or (self.tty and time.monotonic() - self.last_draw >= 0.1):
            self.emit(stage)

    def heartbeat(self):
        while not self.stop.wait(self.interval):
            with self.lock:
                stage = self.stage
            self.emit(stage)

    def __enter__(self):
        if not self.quiet:
            self.worker = threading.Thread(target=self.heartbeat, daemon=True)
            self.worker.start()
        self.emit('Starting diagnostic sanitization')
        return self

    def __exit__(self, *exc):
        self.stop.set()
        if self.worker is not None:
            self.worker.join()
        if self.drawn:
            sys.stderr.write("\n")
            sys.stderr.flush()


def inventory_terms(data, cfg):
    hv = data['_meta']['hostvars']
    names = set(hv)
    for k,v in data.items():
        if k != '_meta' and isinstance(v,dict): names.update(v.get('hosts', []))
    if not names: raise ValueError('Empty inventory')
    terms = set()
    domains = set()
    def add(v):
        if not isinstance(v,str): return
        v = v.rstrip('.')
        try: ipaddress.ip_address(v); return # native IP rule, stable namespace
        except ValueError: pass
        if not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*',v) or len(v)>253: return
        if v.lower() in {'localhost','all','ungrouped'}: return
        terms.update([v,v.lower(),v.upper(),v.split('.')[0],v.split('.')[0].lower(),v.split('.')[0].upper()])
        if '.' in v: domains.add(v.split('.',1)[1].lower())
    for name in names:
        v=hv.get(name,{})
        f=v.get('ansible_facts') or {}
        for x in [name,v.get('ansible_host'),v.get('ansible_hostname'),v.get('ansible_fqdn'),f.get('hostname'),f.get('fqdn')]+[v.get(k) for k in cfg.get('inventory_hostname_vars',[])]: add(x)
        for d in [f.get('domain')]+[v.get(k) for k in cfg.get('inventory_domain_vars', ['ansible_domain','dns_domain','splunk_domain'])]:
            if isinstance(d,str) and re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+',d.rstrip('.')):
                domains.add(d.lower().rstrip('.'))
    exclusions = {d.lower().rstrip('.') for d in cfg.get('inventory_domain_exclusions',[])}
    manual = {d.lower().rstrip('.') for d in cfg.get('domains',[])}
    def covered(d, parents): return any(d == p or d.endswith('.'+p) for p in parents)
    eligible = {d for d in domains if not covered(d, exclusions | manual)}
    added = {d for d in eligible if not covered(d, eligible-{d})}
    return terms, added if cfg.get('inventory_discover_domains',False) else set()

DEFAULT_INDEX_EXCLUSIONS = frozenset({'main', 'summary', 'history'})

def index_terms(paths, exclusions=()):
    """Import custom index names, preserving standard and explicitly excluded names."""
    if not isinstance(exclusions, (list, tuple, set, frozenset)) or not all(
        isinstance(x, str) and re.fullmatch(r'[a-z0-9_-]+', x) for x in exclusions
    ):
        raise ValueError('Invalid index_exclusions')
    excluded = DEFAULT_INDEX_EXCLUSIONS | set(exclusions)
    terms = set()
    for path in paths:
        found = False
        for line in Path(path).read_text(encoding='utf-8-sig').splitlines():
            match = re.fullmatch(r'\s*\[([a-z0-9_-]+)\]\s*(?:[#;].*)?', line)
            if match:
                found = True
                name = match.group(1)
                if name != 'default' and not name.startswith(('_', '-')) and name not in excluded:
                    terms.add(name)
        if not found:
            raise ValueError('Index configuration contains no recognized stanzas')
    return terms

def domain_patterns(domains):
    result=[]
    for d in domains:
        d=d.lower().rstrip('.')
        if not re.fullmatch(r'[a-z0-9_-]+(?:\.[a-z0-9_-]+)+',d): raise ValueError('Invalid DNS suffix')
        result.append(r'(?<![\w.-])(?:[a-zA-Z0-9_-]+\.)*'+''.join('['+c.lower()+c.upper()+']' if c.isalpha() else re.escape(c) for c in d)+r'(?![\w.-])')
    return result

def safe_path(name):
    p=PurePosixPath(name)
    return bool(name) and not p.is_absolute() and not any(x in ('..','.') for x in p.parts) and '\\' not in name and not any(ord(c)<32 for c in name)

def excluded(name):
    p=PurePosixPath(name.lower())
    return p.name in DENY or p.suffix in SUFFIX or any(x in {'kvstore','dispatch','fishbucket'} for x in p.parts)

def allowed_file(name, extensions):
    # Include ordinary numbered log rotations (e.g. splunkd.log.1).
    basename = PurePosixPath(name).name.lower()
    return any(basename.endswith(ext) for ext in extensions) or (
        '.log' in extensions and re.search(r'\.log\.[0-9]+$', basename) is not None)


def run(args):
    with Progress(getattr(args, 'progress_interval', 10), getattr(args, 'quiet', False)) as progress:
        return process(args, progress)

def process(args, progress):
    progress.update('Validating input, key and configuration', True)
    os.umask(0o077)
    jobs, batch_report = plan_jobs(args)
    key = Path(args.key_file).resolve()
    key_bytes = key.read_bytes()
    if not re.fullmatch(rb'[0-9a-fA-F]{64}', key_bytes.strip()):
        raise ValueError('Key must contain 64 hex characters')
    # Snapshot key and resolved policy once for the entire run.
    with tempfile.TemporaryDirectory(prefix='.diag-policy-', dir=jobs[0][1].parent) as td:
        policy = prepare(args, progress, Path(td), key_bytes)
        summaries = []
        files = collections.Counter()
        matches = collections.Counter()
        batch = batch_report is not None
        try:
            for number, (src, out) in enumerate(jobs, 1):
                prefix = f'Diag {number}/{len(jobs)} | Done {number-1}/{len(jobs)} | ' if batch else ''
                summary = process_archive(args, progress, src, out, policy, prefix)
                summaries.append({'archive': out.name, 'report': out.name + '.json', 'status': summary.get('status', 'completed'), 'excluded_timeout': summary['files'].get('excluded_timeout', 0), 'processed_files': summary['processed_files']})
                files.update(summary['files'])
                matches.update(summary['matches_by_rule'])
        except BaseException:
            if batch:
                write_batch_report(batch_report, jobs, summaries, files, matches, policy, 'failed')
            raise
        if batch:
            write_batch_report(batch_report, jobs, summaries, files, matches, policy, 'completed_with_timeouts' if files['excluded_timeout'] else 'completed')
            progress.emit(f'Diags {len(jobs)}/{len(jobs)} | Finished; timeouts: {files["excluded_timeout"]}')
    print(f'Sanitized archive(s) and aggregate report(s) created; timeout exclusions: {files["excluded_timeout"]}. Manual review required.', flush=True)


def plan_jobs(args):
    """Resolve and preflight all destinations; never reuse original basenames in batch."""
    batch_inputs = getattr(args, 'batch_inputs', None)
    input_dir = getattr(args, 'input_dir', None)
    if batch_inputs or input_dir:
        if input_dir:
            directory = Path(input_dir).resolve(strict=True)
            if not directory.is_dir(): raise ValueError('Input directory required')
            sources = sorted(p for p in directory.iterdir() if p.is_file() and p.name.endswith(('.tar.gz', '.tgz')))
        else:
            sources = [Path(p) for p in batch_inputs]
        if not sources: raise ValueError('No input archives')
        destination = Path(args.output_dir).resolve()
        if input_dir and destination == directory: raise ValueError('Input and output directories must differ')
        jobs = [(p.resolve(strict=True), destination / f'diag-{i:04d}.tar.gz') for i,p in enumerate(sources,1)]
        batch_report = destination / 'batch-report.json'
    else:
        jobs = [(Path(args.input).resolve(strict=True), Path(args.output).absolute())]
        batch_report = None
    sources = [src for src,_ in jobs]
    if len(set(sources)) != len(sources) or not all(p.is_file() for p in sources):
        raise ValueError('Input archives must be distinct regular files')
    protected = set(sources) | {Path(args.key_file).resolve()}
    for value in [getattr(args,'config',None),getattr(args,'inventory_json',None),*getattr(args,'indexes_conf',[]),*getattr(args,'inventory',[])]:
        if value: protected.add(Path(value).resolve())
    outputs = [p for _,out in jobs for p in (out,Path(str(out)+'.json'),Path(str(out)+'.timeouts.private.json'))]
    if batch_report: outputs.append(batch_report)
    if len({p.resolve() for p in outputs}) != len(outputs) or any(p.exists() or p.is_symlink() or p.resolve() in protected for p in outputs):
        raise ValueError('Outputs must be new and distinct')
    if batch_report: batch_report.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    return jobs, batch_report


def write_batch_report(path, jobs, summaries, files, matches, policy, status):
    report = {'status':status,'archives_total':len(jobs),'archives_completed':len(summaries),
              'archives':summaries,'files':dict(files),'matches_by_rule':dict(matches),
              **policy['metadata'],'review_required':True}
    if status == 'failed':
        report['failed_archive_number'] = len(summaries)+1
        report['archives_not_completed'] = len(jobs)-len(summaries)
        failed_out = jobs[len(summaries)][1]
        failed_private = Path(str(failed_out)+'.timeouts.private.json')
        if failed_private.is_file():
            report['failed_archive_timeout_report'] = failed_private.name
            report['failed_archive_timeout_count'] = len(json.loads(failed_private.read_text())['files'])
    with path.open('x') as f: json.dump(report,f,indent=2)


def prepare(args, progress, tmp, key_bytes):
    key=tmp/'key'; key.write_bytes(key_bytes)
    cfg=json.loads(Path(args.config).read_text()) if args.config else {}
    extensions=cfg.get('include_extensions', DEFAULT_EXTENSIONS)
    if not isinstance(extensions,list) or not extensions or not all(isinstance(x,str) and re.fullmatch(r'\.[a-zA-Z0-9]+',x) for x in extensions): raise ValueError('Invalid include_extensions')
    extensions={x.lower() for x in extensions}
    terms=set(cfg.get('sensitive_terms',[])); discovered=set()
    if args.inventory or args.inventory_json:
        progress.update('Resolving Ansible inventory', True)
        if args.inventory_json: data=json.loads(Path(args.inventory_json).read_text())
        else:
            cmd=['ansible-inventory','--list']
            for i in args.inventory: cmd+=['-i',i]
            for v in args.vault_id: cmd+=['--vault-id',v]
            r=subprocess.run(cmd,capture_output=True,timeout=120,check=True)
            if r.stderr.strip(): raise ValueError('Inventory emitted diagnostics')
            data=json.loads(r.stdout)
        imported, discovered=inventory_terms(data,cfg); terms.update(imported)
    inventory_count = len(terms)
    indexes = set()
    if getattr(args, 'indexes_conf', []):
        progress.update('Importing index names from configuration', True)
        indexes = index_terms(args.indexes_conf, cfg.get('index_exclusions', []))
        terms.update(indexes)
        progress.update(f'Index discovery complete: {len(indexes)} distinct index names', True)
    progress.update(f'Infrastructure discovery complete: {len(terms)} sensitive terms, {len(discovered)} discovered domains', True)
    patterns=domain_patterns(sorted(set(cfg.get('domains',[])) | discovered))
    rules=cfg.get('rules',RULES)
    if not isinstance(rules,list) or not rules or not all(isinstance(x,str) for x in rules): raise ValueError('Invalid rule list')
    if not all(isinstance(x,str) and x and '\n' not in x and '\r' not in x for x in terms): raise ValueError('Invalid sensitive literal')
    cli=shutil.which(args.cli)
    if not cli: raise ValueError('Install local logtotal-sanitize CLI first')
    extra=tmp/'terms.txt'; custom=tmp/'rules.json'
    extra.write_text('\n'.join(sorted(terms,key=lambda s:(-len(s),s)))+'\n' if terms else '')
    custom.write_text(json.dumps([{'id':'internalDomains','label':'Internal DNS','description':'Configured DNS suffixes','mode':'pseudo','token':'HOST','patterns':patterns}]))
    base=[cli,'--key-file',str(key),'--key-encoding','hex','--rules',','.join(rules),'--quiet','--no-progress']
    if terms: base+=['--redact-file',str(extra)]
    if patterns: base+=['--rules-file',str(custom)]
    if cfg.get('aggressive',False): base+=['--aggressive']
    metadata={'inventory_terms':inventory_count,'index_terms':len(indexes),'sensitive_terms_total':len(terms),'domain_rules':len(patterns),'rules':rules,'include_extensions':sorted(extensions)}
    return {'base':base,'extensions':extensions,'metadata':metadata,'path_cache':{}}


def process_archive(args, progress, src, out, policy, prefix=''):
    report=Path(str(out)+'.json')
    extensions=policy['extensions']; base=policy['base']
    stats=collections.Counter(); counts=collections.Counter(); names=set()
    stats['excluded_timeout'] = 0
    timeouts = []
    processed_files = []
    private_report = Path(str(out)+'.timeouts.private.json')
    timeout = args.timeout or None
    timeout_label = f'{timeout}s' if timeout else 'disabled'
    calls = 0
    total = 0
    candidates = 0
    completed_candidates = 0
    progress.update(prefix+'Counting files in archive (metadata pass)', True)
    with tarfile.open(src, 'r|*') as scan:
        for index, member in enumerate(scan, 1):
            if index > args.max_members: raise ValueError('Archive member limit exceeded')
            if not safe_path(member.name): raise ValueError('Unsafe input path')
            if not member.isdir(): total += 1
            if member.isfile() and not excluded(member.name) and allowed_file(member.name, extensions): candidates += 1
            if index % 100 == 0:
                progress.update(prefix+f'Counting archive entries: {total:,} files found')
    progress.update(prefix+'Preparing archive', True)
    def status(activity):
        skipped = sum(v for k,v in stats.items() if k.startswith('excluded_'))
        done = stats['included'] + skipped
        pct = 100 * completed_candidates / candidates if candidates else 0
        filled = min(20, int(pct / 5))
        bar = '#' * filled + '-' * (20 - filled)
        return (prefix+f'[{bar}] {pct:5.1f}% {completed_candidates:,}/{candidates:,} target files | '
                f'OK {stats["included"]:,} Timeout {stats["excluded_timeout"]:,} Skip {skipped-stats["excluded_timeout"]:,} | {activity}')
    with tempfile.TemporaryDirectory(prefix='.diag-',dir=out.parent) as td:
        tmp=Path(td); archive=tmp/'result.tar.gz'; raw=tmp/'input'; clean=tmp/'output'; rep=tmp/'report.json'
        def sanitize(data, aggregate=False):
            nonlocal calls
            calls += 1
            kind = 'Sanitizing file content' if aggregate else 'Sanitizing archive path component'
            progress.update(status(f'{kind} ({len(data):,} bytes; timeout {timeout_label})'))
            raw.write_bytes(data)
            clean.unlink(missing_ok=True); rep.unlink(missing_ok=True)
            r=subprocess.run(base+[str(raw),'-o',str(clean),'--report',str(rep),'--report-format','json'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=timeout)
            if r.returncode or not clean.is_file() or not rep.is_file():
                progress.emit(f'Sanitizer failed during {kind.lower()} (exit code {r.returncode})')
                raise ValueError('SOC Prime processing failed; no archive released')
            info=json.loads(rep.read_text()); result=clean.read_bytes()
            if aggregate: counts.update(info['counts'])
            rep.unlink(); raw.unlink(); clean.unlink()
            return result
        path_cache=policy['path_cache']
        def path_name(name):
            parts=[]
            for part in PurePosixPath(name).parts:
                # Tokens contain angle brackets and colons: normalize them only in archive names.
                if part not in path_cache: path_cache[part]=sanitize(part.encode()).decode().rstrip('\r\n')
                s=path_cache[part]
                s=re.sub(r'<([A-Z]+):([0-9a-fA-F]+)>',r'\1-\2',s)
                if not safe_path(s) or '/' in s or not s or s in ('.','..') or ':' in s or '<' in s or '>' in s: raise ValueError('Unsafe sanitized path')
                parts.append(s)
            return '/'.join(parts)
        with tarfile.open(src,'r|*') as inp, tarfile.open(archive,'w:gz') as dest:
            for m in inp:
                stats['seen']+=1
                progress.update(status('Reading archive'))
                if stats['seen']>args.max_members: raise ValueError('Archive member limit exceeded')
                if not safe_path(m.name): raise ValueError('Unsafe input path')
                if m.isdir(): continue
                if not m.isfile(): stats['excluded_nonregular']+=1; progress.update(status('Skipping excluded entry')); continue
                if excluded(m.name): stats['excluded_policy']+=1; progress.update(status('Skipping excluded entry')); continue
                if not allowed_file(m.name, extensions): stats['excluded_extension']+=1; progress.update(status('Skipping out-of-scope file')); continue
                if m.size>args.max_mib*1024**2: stats['excluded_size']+=1; completed_candidates+=1; progress.update(status('Skipping excluded entry')); continue
                data=inp.extractfile(m).read()
                try: text=data.decode('utf-8')
                except UnicodeDecodeError: stats['excluded_binary_or_encoding']+=1; completed_candidates+=1; progress.update(status('Skipping excluded entry')); continue
                if any(ord(c)<32 and c not in '\t\n\r\f' for c in text): stats['excluded_binary_or_encoding']+=1; completed_candidates+=1; progress.update(status('Skipping excluded entry')); continue
                stats['input_bytes']+=len(data)
                if stats['input_bytes']>args.max_total_mib*1024**2: raise ValueError('Archive text size limit exceeded')
                stage = 'archive_path'
                started = time.monotonic()
                try:
                    newname=path_name(m.name)
                    if newname in names: raise ValueError('Sanitized archive path collision')
                    stage = 'file_content'
                    result=sanitize(data,True)
                except subprocess.TimeoutExpired:
                    # subprocess.run kills and waits for the child before raising.
                    # Discard every partial output, never copy the original member.
                    for temporary in (raw, clean, rep):
                        temporary.unlink(missing_ok=True)
                    stats['excluded_timeout'] += 1
                    completed_candidates += 1
                    timeouts.append({'original_path': m.name, 'size_bytes': m.size,
                                     'stage': stage, 'timeout_seconds': args.timeout,
                                     'file_elapsed_seconds': round(time.monotonic()-started, 2),
                                     'status': 'excluded_timeout'})
                    # Persist immediately, even if a later non-timeout error aborts.
                    # This report is INTERNAL ONLY and contains sensitive original paths.
                    temp_report = tmp/'timeouts.json'
                    temp_report.write_text(json.dumps({'internal_only': True, 'files': timeouts}, indent=2))
                    if len(timeouts) == 1:
                        os.link(temp_report, private_report)
                        temp_report.unlink()
                    else:
                        os.replace(temp_report, private_report)
                    progress.update(status('File timed out; omitted'), True)
                    continue
                names.add(newname)
                entry=tarfile.TarInfo(newname); entry.size=len(result); entry.mode=0o600; entry.mtime=m.mtime
                progress.update(status('Writing sanitized file'))
                dest.addfile(entry,io.BytesIO(result)); stats['included']+=1; completed_candidates+=1
                processed_files.append({'path': newname, 'input_size_bytes': m.size,
                                        'output_size_bytes': len(result),
                                        'elapsed_seconds': round(time.monotonic()-started, 3),
                                        'status': 'completed'})
                progress.update(status('File completed'))
                if not progress.tty and (stats['included'] == 1 or stats['included'] % 25 == 0):
                    progress.emit(status('Progress'))
        progress.update(status('Archive processing complete; publishing aggregate report'), True)
        if stats['included'] + sum(v for k,v in stats.items() if k.startswith('excluded_')) != total: raise ValueError('Archive changed between passes')
        if completed_candidates != candidates: raise ValueError('Candidate count changed between passes')
        stats['target_files']=candidates
        summary={'status': 'completed_with_timeouts' if timeouts else 'completed', 'files':dict(stats),'processed_files':processed_files,'matches_by_rule':dict(counts),'review_required':True,**policy['metadata']}
        if timeouts:
            summary['internal_timeout_report'] = private_report.name
        if not stats['included']:
            summary['status'] = 'failed_no_files_included'
            with report.open('x') as f: json.dump(summary,f,indent=2)
            raise ValueError('No files included')
        # Do not overwrite existing destinations; remove report if archive publication fails.
        with report.open('x') as f: json.dump(summary,f,indent=2)
        try: os.link(archive,out)
        except BaseException: report.unlink(missing_ok=True); raise
    progress.emit(status('Finished with timeout exclusions' if timeouts else 'Finished successfully'))
    return summary

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('input',nargs='?'); p.add_argument('output',nargs='?'); p.add_argument('--key-file',required=True); p.add_argument('--config'); p.add_argument('--cli',default='logtotal-sanitize'); p.add_argument('-i','--inventory',action='append',default=[]); p.add_argument('--inventory-json'); p.add_argument('--vault-id',action='append',default=[]); p.add_argument('--max-mib',type=int,default=64); p.add_argument('--max-total-mib',type=int,default=4096); p.add_argument('--max-members',type=int,default=50000); p.add_argument('--timeout',type=int,default=1800,help='Seconds per SOC Prime invocation (default: 1800; 0 disables)')
    p.add_argument('--indexes-conf', action='append', default=[], metavar='PATH', help='Import index names from indexes.conf or plain btool indexes list output; repeatable')
    p.add_argument('--progress-interval', type=float, default=1, help='Seconds between heartbeat updates (default: 1)'); p.add_argument('--quiet', action='store_true', help='Suppress progress messages on stderr')
    batch=p.add_mutually_exclusive_group()
    batch.add_argument('--input',dest='batch_inputs',nargs='+',metavar='ARCHIVE',help='Explicit batch input archives')
    batch.add_argument('--input-dir',help='Process .tar.gz and .tgz files directly in directory')
    p.add_argument('--output-dir',help='New output filenames in this directory (batch only)')
    a=p.parse_args()
    if a.batch_inputs or a.input_dir:
        if a.input or a.output or not a.output_dir: p.error('Batch mode requires --output-dir and no positional arguments')
    elif not a.input or not a.output or a.output_dir: p.error('Provide INPUT OUTPUT or use batch mode')
    if not 0 < a.progress_interval < float('inf'): p.error('--progress-interval must be positive and finite')
    if a.timeout < 0: p.error('--timeout must be nonnegative')
    if a.inventory and a.inventory_json: p.error('Use inventory or inventory JSON, not both')
    try: run(a)
    except subprocess.TimeoutExpired: p.exit(1,'A subprocess exceeded its timeout; current archive not published; earlier completed batch outputs may remain.\n')
    except Exception: p.exit(1,'Sanitization failed; verify configuration, local CLI and archive. Earlier completed batch outputs may remain. No raw diagnostics printed.\n')
if __name__=='__main__': main()
