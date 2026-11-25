import io,json,os,sys,tarfile,tempfile,unittest,time,contextlib
from pathlib import Path
from unittest.mock import patch
import sanitize_diag as s
class Tests(unittest.TestCase):
    def test_progress_heartbeat(self):
        output=io.StringIO()
        with contextlib.redirect_stderr(output):
            with s.Progress(interval=0.02) as progress:
                progress.update('Waiting for sanitizer', True)
                time.sleep(0.12)
        self.assertGreaterEqual(output.getvalue().count('Waiting for sanitizer'),2)
    def test_live_progress_rewrites(self):
        output=io.StringIO()
        with contextlib.redirect_stderr(output), patch.object(output, 'isatty', return_value=True):
            with s.Progress(interval=10) as progress:
                progress.update('1/2 files', True)
                progress.update('2/2 files', True)
        value=output.getvalue()
        self.assertIn('\r\x1b[2K',value)
        self.assertIn('2/2 files',value)
        self.assertEqual(value.count('\n'),1)
    def test_progress_quiet(self):
        output=io.StringIO()
        with contextlib.redirect_stderr(output):
            with s.Progress(interval=0.01, quiet=True) as progress:
                progress.update('Waiting for sanitizer', True)
                time.sleep(0.03)
        self.assertEqual(output.getvalue(),'')
    def test_inventory(self):
        terms,domains=s.inventory_terms({'_meta':{'hostvars':{'idx01':{'ansible_host':'idx01.prod.example.com'},'idx02':{'ansible_host':'idx02.other.local'}}}}, {'inventory_discover_domains':True,'domains':['example.com']})
        self.assertIn('idx01.prod.example.com',terms); self.assertEqual(domains,{'other.local'})
    def test_paths(self):
        self.assertFalse(s.safe_path('../etc/passwd')); self.assertFalse(s.safe_path('/etc/passwd')); self.assertTrue(s.safe_path('diag/logs/splunkd.log'))
        self.assertTrue(s.excluded('diag/etc/splunk.secret'))
    def test_file_scope(self):
        for name in ['splunkd.log','server.CONF','metrics.log.2']:
            self.assertTrue(s.allowed_file(name,s.DEFAULT_EXTENSIONS))
        for name in ['module.py','style.css','metrics.log.gz','readme.txt']:
            self.assertFalse(s.allowed_file(name,s.DEFAULT_EXTENSIONS))
        self.assertTrue(s.allowed_file('readme.txt',['.txt']))
        self.assertTrue(s.excluded('diag/passwords.conf'))
    def test_domains(self):
        import re
        p=s.domain_patterns(['example.com'])[0]
        self.assertEqual(re.search(p,'idx.PROD.Example.COM:8089').group(),'idx.PROD.Example.COM')
        self.assertIsNone(re.search(p,'example.com.other.net'))
    def test_index_terms(self):
        with tempfile.TemporaryDirectory() as d:
            a=Path(d)/'a.conf'; b=Path(d)/'b.conf'
            a.write_text('[default]\n[volume:hot]\n[provider:foo]\n[_internal]\n[security_network]\nhomePath = secret\n# [commented]\n[main]\n')
            b.write_text('[security_network]\n[windows-events]\n')
            self.assertEqual(s.index_terms([a,b]),{'security_network','windows-events'})
            b.write_text('[default]\n[_audit]\n')
            self.assertEqual(s.index_terms([b]), set())
            self.assertEqual(s.index_terms([a], ['security_network']), set())
            b.write_text('[main]\n[summary]\n[history]\n[main_prod]\n[custom_kvstore]\n')
            self.assertEqual(s.index_terms([b]), {'main_prod','custom_kvstore'})
            with self.assertRaises(ValueError): s.index_terms([b], 'main')
            b.write_text('not a configuration')
            with self.assertRaises(ValueError): s.index_terms([b])
    def test_archive_mock_cli(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); key=p/'key';key.write_text('a'*64)
            cli=p/'mock-cli';cli.write_text('#!'+sys.executable+'\nimport sys,json,pathlib\na=sys.argv\no=pathlib.Path(a[a.index("-o")+1]); raw=pathlib.Path(a[a.index("-o")-1]); terms=pathlib.Path(a[a.index("--redact-file")+1]).read_text().splitlines(); assert "security_network" in terms and not {"main","summary","history"}.intersection(terms); o.write_bytes(raw.read_bytes().replace(b"10.1.2.3",b"<IP:1234567890abcdef>")); pathlib.Path(a[a.index("--report")+1]).write_text(json.dumps({"counts":{"ips":1},"original":"private"}))\n');cli.chmod(0o700)
            src=p/'in.tar.gz'; out=p/'out.tar.gz'; indexes=p/'indexes.conf'; indexes.write_text('[security_network]\n[main]\n[summary]\n[history]\n')
            with tarfile.open(src,'w:gz') as t:
                for name,content in [('diag/10.1.2.3.log',b'peer=10.1.2.3'),('diag/etc/splunk.secret',b'secret'),('diag/lib/module.py',b'private'),('diag/web/style.css',b'private'),('diag/etc/passwords.conf',b'private')]:
                    m=tarfile.TarInfo(name);m.size=len(content);t.addfile(m,io.BytesIO(content))
            with patch.object(sys,'argv',['x',str(src),str(out),'--key-file',str(key),'--cli',str(cli),'--indexes-conf',str(indexes)]): s.main()
            with tarfile.open(out) as t:
                self.assertEqual(t.getnames(),['diag/IP-1234567890abcdef.log']); self.assertEqual(t.extractfile(t.getmembers()[0]).read(),b'peer=<IP:1234567890abcdef>')
            rep=json.loads(Path(str(out)+'.json').read_text());self.assertEqual(rep['files']['excluded_policy'],2);self.assertNotIn('private',json.dumps(rep)); self.assertEqual(rep['files']['excluded_extension'],2); self.assertEqual(rep['files']['target_files'],1); self.assertEqual(rep['index_terms'],1); self.assertNotIn('security_network',json.dumps(rep))
    def test_batch(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); key=p/'key'; key.write_text('a'*64)
            cli=p/'cli'; cli.write_text('#!'+sys.executable+'\nimport sys,json,pathlib\na=sys.argv; pathlib.Path(a[a.index("-o")+1]).write_bytes(pathlib.Path(a[a.index("-o")-1]).read_bytes().replace(b"secret-host",b"TOKEN")); pathlib.Path(a[a.index("--report")+1]).write_text(json.dumps({"counts":{"hosts":1}}))\n'); cli.chmod(0o700)
            inp=p/'inputs'; inp.mkdir(); out=p/'outputs'
            for name in ['secret-a.tar.gz','secret-b.tgz']:
                with tarfile.open(inp/name,'w:gz') as t:
                    data=b'secret-host'; m=tarfile.TarInfo('diag/splunkd.log'); m.size=len(data); t.addfile(m,io.BytesIO(data))
            argv=['x','--input-dir',str(inp),'--output-dir',str(out),'--key-file',str(key),'--cli',str(cli),'--quiet']
            with patch.object(sys,'argv',argv), patch.object(s,'prepare',wraps=s.prepare) as prepare:
                s.main(); self.assertEqual(prepare.call_count,1)
            for i in (1,2):
                with tarfile.open(out/f'diag-{i:04d}.tar.gz') as t:
                    self.assertEqual(t.extractfile('diag/splunkd.log').read(),b'TOKEN')
            report=json.loads((out/'batch-report.json').read_text()); self.assertEqual(report['archives_completed'],2); self.assertEqual(report['files']['included'],2); self.assertNotIn('secret-',json.dumps(report))
            with patch.object(sys,'argv',argv), self.assertRaises(SystemExit): s.main()
            bad=p/'bad.tar.gz'; bad.write_bytes(b'invalid'); out2=p/'partial'
            with patch.object(sys,'argv',['x','--input',str(inp/'secret-a.tar.gz'),str(bad),'--output-dir',str(out2),'--key-file',str(key),'--cli',str(cli),'--quiet']), self.assertRaises(SystemExit): s.main()
            report=json.loads((out2/'batch-report.json').read_text()); self.assertEqual(report['status'],'failed'); self.assertEqual(report['archives_completed'],1); self.assertFalse((out2/'diag-0002.tar.gz').exists())
if __name__=='__main__': unittest.main()
