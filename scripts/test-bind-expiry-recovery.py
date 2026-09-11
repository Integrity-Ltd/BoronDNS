#!/usr/bin/env python3
"""Bounded loopback BIND/BoronDNS expiry regressions with prebuilt binaries."""
import argparse
import json
import os
from pathlib import Path
import resource
import socket
import subprocess
import time
import tempfile

ZONE = 'expiry.test.'
KEY = 'key "transfer-key." { algorithm hmac-sha256; secret "dG9wc2VjcmV0"; };'

def bound():
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def run(cmd, **kw):
    result = subprocess.run(cmd, text=True, capture_output=True, timeout=10, **kw)
    if result.returncode:
        raise RuntimeError(f'{cmd}: {result.stdout}\n{result.stderr}')
    return result.stdout

def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

def scenario(root, binary, bind_image, label, timers, minimum, signed=False):
    # Evidence may live below a shared/group-writable directory or a long path.
    # Keep administration in a short, private directory independently of it;
    # never chmod caller-owned ancestors or relax the daemon's socket checks.
    with tempfile.TemporaryDirectory(prefix='bds-exp-', dir='/tmp') as directory:
        operator_socket = Path(directory) / 'control.sock'
        _scenario(root, binary, bind_image, label, timers, minimum, signed, operator_socket)


def _scenario(root, binary, bind_image, label, timers, minimum, signed, operator_socket):
    root = root / label
    root.mkdir(mode=0o700)
    pp, dp, rp = port(), port(), port()
    env = {k: v for k, v in os.environ.items() if not k.startswith('BORONDNS_')}
    env['TOKIO_WORKER_THREADS'] = '2'
    processes, handles, events = [], [], []
    start = time.monotonic()

    def event(action, **data):
        row = dict(t=round(time.monotonic()-start, 3), action=action, **data)
        events.append(row)
        print(json.dumps(dict(case=label, **row)), flush=True)

    def spawn(cmd, name):
        handle = (root / name).open('ab')
        handles.append(handle)
        proc = subprocess.Popen(cmd, stdout=handle, stderr=subprocess.STDOUT,
                                env=env, preexec_fn=None if cmd[0] == 'docker' else bound)
        processes.append(proc)
        return proc

    def wait(check, limit=10):
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            for proc in processes:
                if proc.poll() is not None and proc.returncode != 0:
                    raise AssertionError(f'{label}: process exited with {proc.returncode}; see {root}')
            value = check()
            if value:
                return value
            time.sleep(.05)
        raise AssertionError(f'{label}: timeout')

    def command(action):
        return json.loads(run([binary, 'zone', '--socket', str(operator_socket), action, ZONE], env=env))

    def show():
        if not operator_socket.exists():
            return None
        return command('show')

    def state(wanted):
        result = show()
        return result if result and result['state'] == wanted else None

    def observe(action, wanted, limit=10):
        result = wait(lambda: state(wanted), limit)
        event(action, status=result)
        return result

    def answer():
        return run(['dig', '@127.0.0.1', '-p', str(dp), ZONE, 'SOA', '+tries=1', '+time=1', '+noall', '+comments', '+answer'])

    refresh, retry, expire = timers
    (root/'zone.db').write_text(f'''$ORIGIN expiry.test.
$TTL 86400
@ IN SOA ns1.example.test. hostmaster.ns1.example.test. (2023032807 {refresh} {retry} {expire} 3600)
@ IN NS ns1.example.test.
@ IN NS ns2.example.test.
@ IN NS ns3.example.test.
@ IN NS ns4.example.test.
@ IN NS ns5.example.test.
@ IN MX 10 a.mx.example.test.
@ IN MX 10 b.mx.example.test.
@ IN MX 10 c.mx.example.test.
@ IN MX 10 d.mx.example.test.
@ IN TXT "v=spf1 mx include:_spf.example.test -all"
; Synthetic names below, NOT recovered from the original zone.
mail IN A 192.0.2.10
_dmarc IN TXT "v=DMARC1; p=reject"
''')
    zonefile = 'zone.db'
    if signed:
        for flags in [[], ['-f', 'KSK']]:
            run(['dnssec-keygen', '-q', '-a', 'ECDSAP256SHA256', '-n', 'ZONE', *flags, ZONE], cwd=root)
        run(['dnssec-signzone', '-n', '2', '-S', '-o', ZONE, '-f', 'zone.signed', 'zone.db'], cwd=root)
        zonefile = 'zone.signed'
    (root/'named.conf').write_text(f'''{KEY}
controls {{ inet 127.0.0.1 port {rp} allow {{127.0.0.1;}} keys {{"transfer-key.";}}; }};
options {{ directory "{root}"; listen-on port {pp} {{127.0.0.1;}}; listen-on-v6 {{none;}};
recursion no; dnssec-validation no; pid-file "{root}/named.pid"; session-keyfile "{root}/session.key"; }};
zone "{ZONE}" {{type primary; file "{zonefile}"; allow-transfer {{key "transfer-key.";}};
notify explicit; also-notify {{127.0.0.1 port {dp} key "transfer-key.";}}; }};
''')
    (root/'rndc.conf').write_text(KEY + f'\noptions {{default-server 127.0.0.1; default-port {rp}; default-key "transfer-key.";}};\n')
    (root/'borondns.toml').write_text(f'''[server]
operator_socket = "{operator_socket}"
listen_udp = ["127.0.0.1:{dp}"]
listen_tcp = ["127.0.0.1:{dp}"]
zone_cache_directory = "{root}/cache"
log_format = "plain"
[limits]
max_tcp_connections = 16
max_concurrent_transfers = 2
graceful_shutdown_secs = 1
zsm_min_interval_secs = {minimum}
tcp_connect_timeout_secs = 1
axfr_timeout_secs = 3
ixfr_timeout_secs = 3
[transfer]
require_tsig = true
[[tsig_keys]]
name = "transfer-key."
algorithm = "hmac-sha256"
secret = "dG9wc2VjcmV0"
[[zones]]
name = "{ZONE}"
primaries = ["127.0.0.1:{pp}"]
notify_sources = ["127.0.0.1"]
tsig_key = "transfer-key."
''')
    try:
        run(['named-checkconf', str(root/'named.conf')])
        run(['named-checkzone', ZONE, str(root/zonefile)])
        container = f'borondns-expiry-{label}-{os.getpid()}'
        primary_cmd = ['docker', 'run', '--rm', '--name', container, '--network', 'host',
                       '--pull', 'never', '--user', f'{os.getuid()}:{os.getgid()}', '--cap-drop', 'ALL',
                       '--security-opt', 'no-new-privileges', '--memory', '512m', '--cpus', '2',
                       '--pids-limit', '64', '-v', f'{root}:{root}', '--entrypoint', 'named',
                       bind_image, '-g', '-n', '2', '-c', str(root/'named.conf')]
        primary = spawn(primary_cmd, 'primary.log')
        wait(lambda: '\nrunning\n' in (root/'primary.log').read_text() or
             any(line.endswith(' running') for line in (root/'primary.log').read_text().splitlines()))
        server = spawn([binary, 'serve', '--config', str(root/'borondns.toml')], 'server.log')
        observe('initial_active', 'active')
        if expire == 1:
            observe('expired_after_load', 'expired', 4)
            response = answer()
            assert 'status: SERVFAIL' in response, response
            event('expired_query', response=response)
            if minimum == 60 and not signed:
                observe('automatic_same_serial_recovery', 'active', 72)
                observe('expired_again', 'expired', 4)
            event('notify_sent', result=run(['rndc', '-c', str(root/'rndc.conf'), 'notify', ZONE]))
            observe('notify_recovery', 'active', 6)
            response = answer()
            assert 'status: NOERROR' in response and 'flags: qr aa' in response, response
            event('recovered_query', response=response)
            observe('expired_after_notify', 'expired', 4)
            event('refresh_queued', result=command('refresh'))
            observe('refresh_recovery', 'active', 6)
            observe('expired_after_refresh', 'expired', 4)
            event('retransfer_queued', result=command('retransfer'))
            observe('retransfer_recovery', 'active', 6)
        else:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                assert state('active'), 'healthy timer control expired'
                time.sleep(.2)
            event('healthy_timer_control_stable', status=show())
            run(['docker', 'stop', '-t', '3', container])
            primary.wait(timeout=5)
            observe('primary_outage_expired', 'expired', expire + 4)
            primary = spawn(primary_cmd, 'primary.log')
            observe('outage_recovered_same_serial', 'active', 10)
        stop(server)
        event('shutdown', code=server.returncode)
        assert server.returncode == 0
        text = (root/'server.log').read_text()
        assert 'event="zone_expired"' in text
        assert 'last_success_unix_seconds=' in text
        assert 'since_last_attempt_completion_secs=' in text
        if expire == 1:
            for code in ['soa_timers_clamped', 'soa_expiry_before_refresh_or_retry']:
                assert text.count(f'code="{code}"') == 1, f'{label}: expected one {code} warning'
        else:
            assert 'soa_expiry_before_refresh_or_retry' not in text
        time.sleep(2)
        server = spawn([binary, 'serve', '--config', str(root/'borondns.toml')], 'server-restart.log')
        observe('cache_restart_recovered', 'active', 10)
        event('passed')
    finally:
        if 'container' in locals():
            subprocess.run(['docker', 'stop', '-t', '3', container], capture_output=True, timeout=10)
        for proc in reversed(processes):
            stop(proc)
        for handle in handles:
            handle.close()
        (root/'events.json').write_text(json.dumps(events, indent=2)+'\n')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True, help='Parent directory for retained evidence')
    parser.add_argument('--bind-image', required=True, help='Existing local image containing named; no build is performed')
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='bind-expiry-', dir=args.output.resolve()))
    print(f'evidence_directory={root}', flush=True)
    for name, timers, minimum, signed in [
        ('one-second-default', (1, 1, 1), 60, False),
        ('one-second-dnssec', (1, 1, 1), 60, True),
        ('healthy-short-control', (2, 1, 15), 1, True),
    ]:
        scenario(root, str(Path(args.binary).resolve()), args.bind_image, name, timers, minimum, signed)

if __name__ == '__main__':
    main()
