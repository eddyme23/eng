"""Opt-in Linux kernel checks, isolated with unshare --net; never touch host rules."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'linux' and os.environ.get('ENG_RUN_FIREWALL_NS_TEST') == '1',
                     'opt-in Linux network-namespace test')
class KernelCatchallTest(unittest.TestCase):
    def test_real_backends_restart_restore_and_capability_boundary(self):
        if os.geteuid() != 0 or not all(shutil.which(x) for x in ('unshare', 'nft', 'setpriv')):
            self.skipTest('root, unshare, nft and setpriv required')
        permission = subprocess.run(['unshare', '--net', '--', 'true'], capture_output=True)
        if permission.returncode:
            self.skipTest('network namespace creation unavailable')
        # Run all firewall operations in the child network namespace. Do not call
        # cleanup.main(): persistence paths and host systemd services stay untouched.
        code = r"""
import importlib.util, shutil, subprocess, sys
from pathlib import Path
root=Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('cleanup',root/'legacy-udp-cleanup.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def run(args,check=True):
    return subprocess.run(args,check=check,capture_output=True,text=True,timeout=10)
run(['nft','add','table','ip','frimps_v6_udp'])
assert m.native_ready(False)  # No SocksIP table exists or is required.
active=[]
for name in m.TOOLS:
    tool=shutil.which(name)
    if not tool:continue
    result=run([tool,'-w','5','-t','nat','-S','PREROUTING'],False)
    if result.returncode:
        if any(s in result.stderr.lower() for s in ('table does not exist','address family not supported','protocol not supported')):continue
        raise RuntimeError(result.stderr)
    active.append(tool)
assert active, 'no usable iptables frontend in namespace'
rule=['PREROUTING','-i','lo','-p','udp','--dport','1:65535','-j','DNAT','--to-destination',':36717']
good=['PREROUTING','-i','lo','-p','udp','--dport','50001:65535','-j','DNAT','--to-destination',':36717']
for tool in active:run([tool,'-w','5','-t','nat','-A',*good])
# Fresh start, restart and reboot-style restore each may recreate the old rule.
for stage in ('fresh','restart','reboot-restore'):
    for tool in active:
        run([tool,'-w','5','-t','nat','-A',*rule])
        run([tool,'-w','5','-t','nat','-A',*rule])
    m.clean_runtime('lo')
    m.clean_runtime('lo')
    for tool in active:
        result=run([tool,'-w','5','-t','nat','-S','PREROUTING'])
        assert not any(m.obsolete(line,'lo') for line in result.stdout.splitlines())
        assert run([tool,'-w','5','-t','nat','-C',*good],False).returncode==0
        # Same capability removed by the installed UDP Custom service drop-in.
        denied=run(['setpriv','--bounding-set=-net_admin',tool,'-w','5','-t','nat','-A',*rule],False)
        assert denied.returncode!=0, 'transport retained firewall administration capability'
    print('PASS kernel stage:',stage)
print('Host firewall and production VPN configuration were not accessed.')
"""
        result = subprocess.run(['unshare', '--net', '--', sys.executable, '-c', code, str(ROOT)],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
