import os
import shutil
import subprocess
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
BASH = r"C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash")

class BhttpPolicyTest(unittest.TestCase):
    def test_memory_tier_boundaries(self):
        policy = (ROOT / "bhttp-policy.sh").read_text(encoding="utf-8")
        for memory, sessions in [(512,512),(767,512),(768,1024),(1536,2048),(3072,4096),(6144,8192),(32768,8192)]:
            result = subprocess.run([BASH,"-c",policy + f"\nbhttp_policy {memory}; echo $BHTTP_POLICY_SESSIONS $BHTTP_POLICY_MEMORY_MB"],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.strip(), f"{sessions} {min(memory//2,4096)}")

    def test_failed_activation_restores_engine_and_policy(self):
        updater = (ROOT / "apply-bhttp-updates.sh").read_text(encoding="utf-8")
        # Sandbox only the external boundaries; run actual staging, mutation and recovery.
        updater = updater[updater.index('restore() {'):]
        policy = (ROOT / "bhttp-policy.sh").read_text(encoding="utf-8")
        setup = r"""
set -euo pipefail
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
script_dir="$root/scripts"; state_dir="$root/state"; base="$root/backups"
unit="$root/frimps-bhttp.service"; binary="$root/bhttp-server"
mkdir -p "$script_dir" "$state_dir"
printf 'old-engine' > "$binary"
chmod 755 "$binary"
printf 'Restart=on-failure\nRestartSec=5s\nLimitNOFILE=4096\nMemoryMax=384M\nExecStart=/old --max-sessions 128\n' > "$unit"
printf 'BHTTP_PORT=90\nBHTTP_MAX_SESSIONS=128\n' > "$state_dir/bhttp.env"
cp "$unit" "$root/original-unit"
printf '#!/bin/bash\nif [[ ! -f %s/attempted ]]; then touch %s/attempted; exit 1; fi\n' "$root" "$root" > "$script_dir/restart-bhttp.sh"
printf '#!/bin/bash\nexit 0\n' > "$script_dir/refresh-menu-v6.sh"
curl() { local target; while (($#)); do if [[ $1 == -o ]]; then target="$2"; break; fi; shift; done; printf '#!/bin/bash\nexit 0\n' > "$target"; }
sha256sum() { cat >/dev/null; return 0; }
systemd-analyze() { return 0; }
systemctl() { return 0; }
uname() { echo x86_64; }
awk() { echo 2048; }
timeout() { shift; "$@"; }
"""
        # Materialize the shared policy before running the updater in a child shell.
        code = setup + "\ncat > \"$script_dir/bhttp-policy.sh\" <<'POLICY'\n" + policy + "\nPOLICY\n"
        code += "set +e\n( set -e; \n" + updater + "\n)\nresult=$?\nset -e\ntest $result = 1\ntest \"$(cat \"$binary\")\" = old-engine\ncmp \"$unit\" \"$root/original-unit\"\ngrep -q BHTTP_MAX_SESSIONS=128 \"$state_dir/bhttp.env\"\n"
        result = subprocess.run([BASH,"-c",code],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

if __name__ == "__main__": unittest.main()
