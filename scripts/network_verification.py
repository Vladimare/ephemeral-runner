#!/usr/bin/env python3
"""Opt-in, non-destructive network verification for disposable Linux hosts.

This harness is intentionally conservative: it does not install firewall rules,
flush tables, or assume that a named Docker bridge is isolated. Report a result
for each target and fail closed when the backend, DNS or test target is unknown.
"""

import argparse
import errno
import json
import socket
import subprocess
import sys
from typing import Any, Mapping, Sequence

VALID_STATUSES = ('BLOCKED', 'REACHABLE', 'INCONCLUSIVE', 'NOT_TESTED')
DEFAULT_TARGETS = (
    {'name': 'host-gateway', 'family': 4, 'port': 443, 'target': 'gateway'},
    {'name': 'host-local', 'family': 4, 'port': 22, 'target': '127.0.0.1'},
    {'name': 'ipv6', 'family': 6, 'port': 443, 'target': '::1'},
)


def normalize_status(value: Any) -> str:
    if value is None:
        return 'NOT_TESTED'
    text = str(value).strip().upper()
    aliases = {
        'OK': 'REACHABLE',
        'REACHABLE': 'REACHABLE',
        'BLOCKED': 'BLOCKED',
        'FILTERED': 'BLOCKED',
        'TIMED_OUT': 'BLOCKED',
        'TIMEOUT': 'BLOCKED',
        'INCONCLUSIVE': 'INCONCLUSIVE',
        'UNKNOWN': 'INCONCLUSIVE',
        'NOT-TESTED': 'NOT_TESTED',
        'NOT_TESTED': 'NOT_TESTED',
    }
    return aliases.get(text, 'INCONCLUSIVE')


def classify_probe(*, status: Any = None, target: Any = None, family: Any = None,
                   ipv6_enabled: bool | None = None, firewall_backend: Any = None,
                   dns_ok: bool = True, target_exists: bool = True,
                   result: Any = None, reason: str | None = None) -> str:
    """Classify a probe result without assuming that any firewall is in effect.

    A target that is absent, a DNS resolution failure or an unrecognised firewall
    backend is treated as INCONCLUSIVE. Untested IPv6 is NOT_TESTED rather than
    assumed safe or blocked.
    """
    normalized = normalize_status(status)
    if normalized in {'BLOCKED', 'REACHABLE'}:
        return normalized
    if result is not None:
        normalized = normalize_status(result)
        if normalized in {'BLOCKED', 'REACHABLE'}:
            return normalized

    if family == 6 and ipv6_enabled is False:
        return 'NOT_TESTED'
    if family == 6 and ipv6_enabled is None:
        return 'NOT_TESTED'
    backend = str(firewall_backend or '').strip().lower()
    if backend and backend not in {'iptables', 'nftables', 'docker', 'unknown'}:
        return 'INCONCLUSIVE'
    if backend == 'unknown':
        return 'INCONCLUSIVE'
    if not dns_ok:
        return 'INCONCLUSIVE'
    if not target_exists:
        return 'INCONCLUSIVE'
    if target is None and normalized == 'NOT_TESTED':
        return 'NOT_TESTED'
    if normalized == 'NOT_TESTED':
        return 'NOT_TESTED'
    if reason and 'dns' in reason.lower():
        return 'INCONCLUSIVE'
    if reason and 'missing' in reason.lower():
        return 'INCONCLUSIVE'
    return 'INCONCLUSIVE'


def probe_target(host: str, *, port: int = 443, family: int | None = None, timeout: float = 1.0) -> Mapping[str, Any]:
    """Attempt a simple socket connection to a known listener.

    Any connection refusal is treated as inconclusive, not a firewall proof, because
    the service may not be listening at that address/port.
    """
    if not host:
        raise ValueError('host is required')
    if family is None:
        families = (socket.AF_INET, socket.AF_INET6)
    else:
        families = (family,)
    for family_id in families:
        sock = None
        try:
            sock = socket.socket(family_id, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            return {'status': 'REACHABLE', 'host': host, 'port': port, 'family': family_id}
        except socket.timeout:
            return {'status': 'BLOCKED', 'host': host, 'port': port, 'family': family_id, 'reason': 'timed out'}
        except ConnectionRefusedError:
            return {'status': 'INCONCLUSIVE', 'host': host, 'port': port, 'family': family_id, 'reason': 'connection refused'}
        except OSError as error:
            if getattr(error, 'errno', None) in {errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL}:
                continue
            return {'status': 'INCONCLUSIVE', 'host': host, 'port': port, 'family': family_id, 'reason': str(error)}
        finally:
            if sock is not None:
                sock.close()
    return {'status': 'NOT_TESTED', 'host': host, 'port': port, 'family': family, 'reason': 'no usable address family'}


def verify_targets(targets: Sequence[Mapping[str, Any]] | None = None, *, firewall_backend: Any = None,
                   dns_ok: bool = True, ipv6_enabled: bool | None = None) -> list[dict[str, Any]]:
    """Verify a set of operator-specified, known-listening targets."""
    if targets is None:
        targets = DEFAULT_TARGETS
    results = []
    for target in targets:
        name = str(target.get('name') or 'probe')
        host = target.get('target')
        family = target.get('family')
        port = int(target.get('port', 443))
        if host is None or host == 'gateway':
            result = {'status': 'NOT_TESTED', 'name': name, 'reason': 'missing target'}
        else:
            result = probe_target(host, port=port, family=family)
        status = classify_probe(
            status=result.get('status'),
            target=host,
            family=family,
            ipv6_enabled=ipv6_enabled,
            firewall_backend=firewall_backend,
            dns_ok=dns_ok,
            target_exists=bool(host),
            reason=result.get('reason'),
        )
        entry = {'name': name, 'status': status, 'target': host, 'family': family, 'port': port,
                 'reason': result.get('reason', '')}
        if 'status' in result:
            entry['probe_status'] = result['status']
        results.append(entry)
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true', help='emit JSON instead of human-readable output')
    parser.add_argument('--backend', default='unknown', help='firewall backend as reported by Docker or host: iptables/nftables/docker/unknown')
    parser.add_argument('--dns-ok', action='store_true', default=True, help='set to confirm DNS works for the selected targets')
    parser.add_argument('--dns-fail', action='store_false', dest='dns_ok', help='treat DNS as failed (fail-closed)')
    parser.add_argument('--ipv6-enabled', action='store_true', default=None, help='mark IPv6 as available when enabled on this host')
    parser.add_argument('--no-ipv6', action='store_false', dest='ipv6_enabled', help='mark IPv6 as unavailable and report NOT_TESTED')
    parser.add_argument('--target', action='append', default=[], help='add a target in host:port form (for example 127.0.0.1:22 or [::1]:443)')
    args = parser.parse_args(argv)
    targets = []
    for entry in args.target:
        if ':' not in entry:
            raise ValueError('target must be in host:port format')
        host, port = entry.rsplit(':', 1)
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]
        targets.append({'name': host, 'target': host, 'port': int(port), 'family': 6 if ':' in host else 4})
    if not targets:
        targets = list(DEFAULT_TARGETS)
    report = verify_targets(targets, firewall_backend=args.backend, dns_ok=args.dns_ok, ipv6_enabled=args.ipv6_enabled)
    if args.json:
        json.dump({'statuses': report, 'backend': args.backend, 'dns_ok': args.dns_ok, 'ipv6_enabled': args.ipv6_enabled}, sys.stdout, indent=2, sort_keys=True)
        print()
        return 0
    for row in report:
        print(f"{row['name']}: {row['status']} ({row.get('reason') or 'no reason'})")
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        raise SystemExit(1)
