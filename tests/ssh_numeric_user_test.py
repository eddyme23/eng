import os, shutil, subprocess, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASH=r"C:/Program Files/Git/bin/bash.exe" if os.name=="nt" else shutil.which("bash")
SOURCE=(ROOT/'ssh-accounts.sh').read_text(encoding='utf-8')
VALID=SOURCE[SOURCE.index('valid_user()'):SOURCE.index('account_uid_by_name()')]
CREATE=SOURCE[SOURCE.index('create_system_account()'):SOURCE.index('valid_days()')]
DELETE=SOURCE[SOURCE.index('delete_system_account()'):SOURCE.index('case "$action" in')]
class NumericUserTest(unittest.TestCase):
 def test_validation(self):
  for name in ['12345','00123','1eddy','eddy','user_1']:
   r=subprocess.run([BASH,'-c',VALID+'\nvalid_user "$1"','test',name]);self.assertEqual(r.returncode,0,name)
  for name in ['','-1','../123','1 2','1:2','a'*33]:
   r=subprocess.run([BASH,'-c',VALID+'\nvalid_user "$1"','test',name]);self.assertNotEqual(r.returncode,0,name)
 def test_numeric_useradd_uses_badname_without_assigning_numeric_uid(self):
  code=VALID+CREATE+'\nuseradd() { printf "%s\\n" "$@"; }; create_system_account 12345'
  r=subprocess.run([BASH,'-c',code],capture_output=True,text=True)
  self.assertEqual(r.returncode,0,r.stderr);self.assertIn('--badname',r.stdout.splitlines());self.assertNotIn('-u',r.stdout.splitlines())
 def test_delete_uses_resolved_uid_instead_of_numeric_login(self):
  code=VALID+DELETE+r'''
account_uid_by_name() { echo 2345; }
id() { echo 'unsafe numeric lookup' >&2; return 1; }
usermod() { :; }; chage() { :; }; pgrep() { return 1; }
pkill() { echo "$*"; }; userdel() { echo "deleted $*"; }
delete_system_account 1000
'''
  r=subprocess.run([BASH,'-c',code],capture_output=True,text=True)
  self.assertEqual(r.returncode,0,r.stderr);self.assertIn('-TERM -u 2345',r.stdout);self.assertIn('deleted -r 1000',r.stdout)
 def test_system_uid_is_still_protected(self):
  code=VALID+DELETE+r'''
account_uid_by_name() { echo 0; }
userdel() { echo 'should not delete'; }
delete_system_account 12345
'''
  r=subprocess.run([BASH,'-c',code],capture_output=True,text=True)
  self.assertNotEqual(r.returncode,0);self.assertNotIn('should not delete',r.stdout)
if __name__=='__main__':unittest.main()
