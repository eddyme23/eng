import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class UdpRangesTest(unittest.TestCase):
    def test_all_ports_preserve_dedicated_protocols(self):
        source = (ROOT / 'udp-routing.sh').read_text(encoding='utf-8')
        rules = re.findall(r'udp dport (\d+-\d+) dnat to (\S+)', source)
        def resolve(port):
            if port in (53, 443, 1194, 4000):
                return 'direct'
            for span, target in rules:
                lo, hi = map(int, span.split('-'))
                if lo <= port <= hi:
                    return target
            return 'unallocated'
        for port in range(1, 65536):
            if port in (53, 443, 1194, 4000): expected = 'direct'
            elif 1195 <= port <= 3999: expected = '169.254.240.2'
            elif 6000 <= port <= 19999: expected = ':5667'
            elif 20000 <= port <= 50000: expected = ':36712'
            elif 50001 <= port <= 65535: expected = ':36717'
            else: expected = 'unallocated'
            self.assertEqual(resolve(port), expected, port)
        self.assertIn('udp dport { 53, 443, 1194, 4000 } accept', source)
        self.assertIn('iifname "$public_if" udp accept', source)
        for script in ('udp-routing.sh', 'socksip-network.sh', 'wireguard-nat.sh'):
            self.assertNotIn('iptables', (ROOT / script).read_text(encoding='utf-8').replace('legacy iptables rules', 'legacy rules'))

    def test_metadata_matches_ranges(self):
        text = (ROOT / 'install-v6.sh').read_text(encoding='utf-8')
        body = re.search(r'cat > "\$state_dir/routes.json" <<EOF\n(.*?)\nEOF', text, re.S).group(1)
        data = json.loads(body)
        self.assertEqual(data['udpCustomRanges'], ['50001-65535'])
        self.assertEqual(data['socksipRanges'], ['1195-3999'])
        self.assertIn('socksip', data['protocols'])


if __name__ == '__main__':
    unittest.main()
