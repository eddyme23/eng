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

if __name__ == "__main__":
    unittest.main()
