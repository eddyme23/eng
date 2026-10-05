import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class UdpRangesTest(unittest.TestCase):
    def test_all_ports_preserve_dedicated_protocols(self):
        source = (ROOT / 'udp-routing.sh').read_text(encoding='utf-8')
        rules = re.findall(r'add "\$chain" -p udp --dport (\d+(?::\d+)?) -j (ACCEPT|DNAT)(?: --to-destination (\S+))?', source)
        def resolve(port):
            for span, action, target in rules:
                lo, _, hi = span.partition(':')
                if int(lo) <= port <= int(hi or lo):
                    return target if action == 'DNAT' else 'direct'
            return 'unallocated'
        for port in range(1, 65536):
            if port in (53, 443, 1194, 4000): expected = 'direct'
            elif 1195 <= port <= 3999: expected = '169.254.240.2'
            elif 6000 <= port <= 19999: expected = ':5667'
            elif 20000 <= port <= 50000: expected = ':36712'
            elif 50001 <= port <= 65535: expected = ':36717'
            else: expected = 'unallocated'
            self.assertEqual(resolve(port), expected, port)
        self.assertIn('add "$chain" -p udp -j ACCEPT', source)
        nft_rules = re.findall(r'udp dport (\d+-\d+) dnat to (\S+)', source)
        iptables_ranges = [(span.replace(':', '-'), target) for span, action, target in rules if ':' in span and action == 'DNAT']
        self.assertEqual(sorted(nft_rules), sorted(iptables_ranges))

    def test_metadata_matches_ranges(self):
        text = (ROOT / 'install-v6.sh').read_text(encoding='utf-8')
        body = re.search(r'cat > "\$state_dir/routes.json" <<EOF\n(.*?)\nEOF', text, re.S).group(1)
        data = json.loads(body)
        self.assertEqual(data['udpCustomRanges'], ['50001-65535'])
        self.assertEqual(data['socksipRanges'], ['1195-3999'])
        self.assertIn('socksip', data['protocols'])


if __name__ == '__main__':
    unittest.main()
