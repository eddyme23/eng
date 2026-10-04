import re
import unittest
from pathlib import Path

class RoutingTemplateTest(unittest.TestCase):
    def test_haproxy_sections_and_routes(self):
        source=(Path(__file__).resolve().parents[1]/'render-routing.sh').read_text(encoding='utf-8')
        config=re.search(r'haproxy-443.cfg" <<EOF\n(.*?)\nEOF',source,re.S).group(1)
        sections=re.findall(r'^(frontend|backend|listen) (\S+)',config,re.M)
        self.assertEqual(len(sections),len(set(sections)), 'duplicate HAProxy section')
        backends={name for kind,name in sections if kind=='backend'}
        for name in re.findall(r'default_backend (\S+)',config):
            self.assertIn(name,backends)
        self.assertEqual(backends,{'ssh_http_gateway','main_tls_router'})
        self.assertIn('server ssh_http_gateway 127.0.0.1:3102',config)
        for port in [80,443,8080,8880,2082,2086]:
            self.assertIn('bind :'+str(port)+'\n',config)
        self.assertNotIn('inspect-delay',config)
        self.assertIn('-openvpn-target 127.0.0.1:10081',source)

if __name__=='__main__':unittest.main()
