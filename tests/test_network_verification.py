import unittest

from scripts import network_verification as net


class NetworkVerificationTests(unittest.TestCase):
    def test_fail_closed_for_untested_ipv6_unknown_backend_dns_and_missing_targets(self):
        self.assertEqual('NOT_TESTED', net.classify_probe(family=6, ipv6_enabled=None, firewall_backend='unknown', dns_ok=True, target_exists=True))
        self.assertEqual('INCONCLUSIVE', net.classify_probe(family=4, ipv6_enabled=True, firewall_backend='unknown', dns_ok=True, target_exists=True))
        self.assertEqual('INCONCLUSIVE', net.classify_probe(family=4, ipv6_enabled=True, firewall_backend='iptables', dns_ok=False, target_exists=True))
        self.assertEqual('INCONCLUSIVE', net.classify_probe(family=4, ipv6_enabled=True, firewall_backend='iptables', dns_ok=True, target_exists=False, target=None))

    def test_reachable_and_blocked_statuses_are_preserved(self):
        self.assertEqual('REACHABLE', net.normalize_status('reachable'))
        self.assertEqual('BLOCKED', net.normalize_status('timed_out'))
        self.assertEqual('BLOCKED', net.classify_probe(status='BLOCKED', family=4, ipv6_enabled=True, firewall_backend='nftables', dns_ok=True, target_exists=True))
        self.assertEqual('REACHABLE', net.classify_probe(status='REACHABLE', family=4, ipv6_enabled=True, firewall_backend='iptables', dns_ok=True, target_exists=True))

    def test_probe_target_treats_connection_refused_as_inconclusive(self):
        result = net.probe_target('127.0.0.1', port=1, timeout=0.05)
        self.assertIn(result['status'], ('INCONCLUSIVE', 'BLOCKED', 'REACHABLE'))
        self.assertIn(result.get('reason', ''), ('connection refused', 'timed out', ''))

    def test_verify_targets_report_fail_closed_classes(self):
        report = net.verify_targets([
            {'name': 'missing', 'target': None, 'port': 443, 'family': 4},
            {'name': 'dns-fail', 'target': 'example.invalid', 'port': 443, 'family': 4},
            {'name': 'ipv6-untested', 'target': '::1', 'port': 443, 'family': 6},
        ], firewall_backend='unknown', dns_ok=True, ipv6_enabled=None)
        statuses = {entry['name']: entry['status'] for entry in report}
        self.assertEqual('INCONCLUSIVE', statuses['missing'])
        self.assertEqual('INCONCLUSIVE', statuses['dns-fail'])
        self.assertEqual('NOT_TESTED', statuses['ipv6-untested'])


if __name__ == '__main__':
    unittest.main()
