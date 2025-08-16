#!/usr/bin/env python3
# Mininet emulation of RPL-like scenarios to demonstrate Black Hole behaviors
# Topology:
#   h1 (sink) connected to router n5 and router n6
#   n5 connects to leaves h2, h3  (affected by malicious behavior on n5)
#   n6 connects to leaf h4        (unaffected branch)
#
# Links are point-to-point /30 subnets. Routers are Hosts with IP forwarding enabled.
# We do not model RPL/DIO. We emulate multi-hop routes + malicious dropping via iptables.
#
# Scenarios:
#   1) Clear network: no drops, all forwarding works
#   2) Selective forwarding: n5 drops FORWARD chain traffic (neighbors' packets) but can send its own
#   3) Complete black hole: n5 drops FORWARD and OUTPUT (no own traffic either)

import re, json, csv, time, sys, argparse
from mininet.net import Mininet
from mininet.node import Host
from mininet.link import TCLink
from mininet.log import setLogLevel, info

def set_ip(node, intf, cidr):
    node.cmd(f'ip addr flush dev {intf}')
    node.cmd(f'ip addr add {cidr} dev {intf}')
    node.cmd(f'ip link set {intf} up')

def add_route(node, route):
    node.cmd(route)

def enable_forwarding(node):
    node.cmd('sysctl -w net.ipv4.ip_forward=1 >/dev/null')

def flush_iptables(node):
    node.cmd('iptables -F')
    node.cmd('iptables -t nat -F')
    node.cmd('iptables -t mangle -F')
    node.cmd('iptables -X')

def scenario_rules(node, scenario):
    """Configure iptables on malicious router n5 according to scenario."""
    flush_iptables(node)
    if scenario == 1:
        # Clear network: no drops
        return
    elif scenario == 2:
        # Selective forwarding: drop all forwarded traffic
        node.cmd('iptables -A FORWARD -j DROP')
    elif scenario == 3:
        # Complete black hole: drop forwarded traffic and own outgoing
        node.cmd('iptables -A FORWARD -j DROP')
        node.cmd('iptables -A OUTPUT -j DROP')

def ping_and_parse(src, dst_ip, count=8, timeout=None):
    if timeout is None:
        timeout = count + 4
    out = src.cmd(f'ping -c {count} -w {timeout} {dst_ip}')
    # Parse transmitted/received
    m = re.search(r'(\d+)\s+packets transmitted,\s+(\d+)\s+received', out)
    sent = int(m.group(1)) if m else count
    recv = int(m.group(2)) if m else 0
    pdr = (recv / sent) if sent else 0.0
    # Parse rtt avg
    avg = None
    m2 = re.search(r'rtt min/avg/max/(?:mdev|stddev) = [\d\.]+/([\d\.]+)/', out)
    if m2:
        try:
            avg = float(m2.group(1))
        except:
            avg = None
    return {'sent': sent, 'recv': recv, 'pdr': pdr, 'rtt_avg_ms': avg, 'raw': out}

def build_net():
    net = Mininet(link=TCLink, build=False, autoSetMacs=True, autoStaticArp=True)
    # Nodes
    h1 = net.addHost('h1')  # sink
    n5 = net.addHost('n5')  # router (malicious in scenarios 2 & 3)
    n6 = net.addHost('n6')  # router (benign)
    h2 = net.addHost('h2')  # leaf via n5
    h3 = net.addHost('h3')  # leaf via n5
    h4 = net.addHost('h4')  # leaf via n6

    # Links (order matters for interface naming)
    # h1<->n5
    net.addLink(h1, n5, bw=10, delay='5ms')
    # h1<->n6
    net.addLink(h1, n6, bw=10, delay='5ms')
    # n5<->h2
    net.addLink(n5, h2, bw=5, delay='10ms')
    # n5<->h3
    net.addLink(n5, h3, bw=5, delay='12ms')
    # n6<->h4
    net.addLink(n6, h4, bw=5, delay='8ms')

    net.build()
    net.start()

    # Interfaces come up as: h1-eth0(n5), h1-eth1(n6)
    # Assign IPs (/30 per link)
    set_ip(h1, 'h1-eth0', '10.0.15.1/30')  # to n5
    set_ip(h1, 'h1-eth1', '10.0.16.1/30')  # to n6

    set_ip(n5, 'n5-eth0', '10.0.15.2/30')  # to h1
    set_ip(n5, 'n5-eth1', '10.0.52.1/30')  # to h2
    set_ip(n5, 'n5-eth2', '10.0.53.1/30')  # to h3

    set_ip(n6, 'n6-eth0', '10.0.16.2/30')  # to h1
    set_ip(n6, 'n6-eth1', '10.0.64.1/30')  # to h4

    set_ip(h2, 'h2-eth0', '10.0.52.2/30')
    set_ip(h3, 'h3-eth0', '10.0.53.2/30')
    set_ip(h4, 'h4-eth0', '10.0.64.2/30')

    # Enable forwarding on routers
    enable_forwarding(n5)
    enable_forwarding(n6)

    # Routes on sink: point subnets via corresponding routers
    add_route(h1, 'ip route add 10.0.52.0/30 via 10.0.15.2 dev h1-eth0')
    add_route(h1, 'ip route add 10.0.53.0/30 via 10.0.15.2 dev h1-eth0')
    add_route(h1, 'ip route add 10.0.64.0/30 via 10.0.16.2 dev h1-eth1')

    # Default routes on leaves through their parent routers
    add_route(h2, 'ip route add default via 10.0.52.1 dev h2-eth0')
    add_route(h3, 'ip route add default via 10.0.53.1 dev h3-eth0')
    add_route(h4, 'ip route add default via 10.0.64.1 dev h4-eth0')

    # Optional: routes on routers for own convenience (not strictly required)
    add_route(n5, 'ip route add default via 10.0.15.1 dev n5-eth0')
    add_route(n6, 'ip route add default via 10.0.16.1 dev n6-eth0')

    return net, h1, n5, n6, h2, h3, h4

def run_scenario(scenario):
    net, h1, n5, n6, h2, h3, h4 = build_net()

    # Configure malicious behavior on n5
    scenario_rules(n5, scenario)

    tests = []
    def add_test(src, dst_ip, label):
        r = ping_and_parse(src, dst_ip, count=8)
        r['src'] = src.name
        r['dst_ip'] = dst_ip
        r['label'] = label
        tests.append(r)
        info(f"  {label}: {src.name} -> {dst_ip} | sent={r['sent']} recv={r['recv']} pdr={r['pdr']:.2f} rtt_avg_ms={r['rtt_avg_ms']}\n")

    info(f"\n=== Scenario {scenario} ===\n")
    # Affected leaves (via n5) ping sink (h1-eth0 IP)
    add_test(h2, '10.0.15.1', 'affected_leaf_h2_to_sink')
    add_test(h3, '10.0.15.1', 'affected_leaf_h3_to_sink')
    # Unaffected leaf (via n6)
    add_test(h4, '10.0.16.1', 'unaffected_leaf_h4_to_sink')
    # Malicious router itself ping sink (only in scenarios 1-2 it should work)
    add_test(n5, '10.0.15.1', 'malicious_router_n5_to_sink')

    # Summaries
    summary = {}
    for t in tests:
        key = t['label']
        summary[key] = {
            'pdr': t['pdr'],
            'avg_rtt_ms': t['rtt_avg_ms']
        }

    # Clean up
    net.stop()
    return tests, summary

def run_all():
    all_results = {}
    summaries = {}
    for s in (1, 2, 3):
        tests, summary = run_scenario(s)
        all_results[f'scenario_{s}'] = tests
        summaries[f'scenario_{s}'] = summary

    # Save JSON and CSV
    with open('results.json', 'w') as f:
        json.dump(all_results, f, indent=2)

    with open('results.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['scenario', 'src', 'dst_ip', 'label', 'sent', 'recv', 'pdr', 'rtt_avg_ms'])
        for scen_key, tests in all_results.items():
            for t in tests:
                writer.writerow([scen_key, t['src'], t['dst_ip'], t['label'], t['sent'], t['recv'], f"{t['pdr']:.3f}", t['rtt_avg_ms'] if t['rtt_avg_ms'] is not None else ''])

    print("\n=== Summaries ===")
    print(json.dumps(summaries, indent=2))

if __name__ == '__main__':
    setLogLevel('info')
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--scenario', type=int, choices=[1,2,3], help='Run a single scenario (1,2,3)')
    ap.add_argument('--run-all', action='store_true', help='Run all three scenarios sequentially')
    args = ap.parse_args()

    if args.run_all:
        run_all()
    elif args.scenario:
        tests, summary = run_scenario(args.scenario)
        print(json.dumps(summary, indent=2))
    else:
        print("Usage:\n  sudo python3 rpl_blackhole_mininet.py --run-all\n  sudo python3 rpl_blackhole_mininet.py --scenario 2")
