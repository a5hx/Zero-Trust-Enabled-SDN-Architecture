#!/usr/bin/env python3
import subprocess, re, sys

def get_flows(switch):
    out = subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch],
        capture_output=True, text=True
    ).stdout
    rows = []
    for line in out.splitlines():
        if "cookie=" not in line:
            continue
        in_port = re.search(r'in_port="?([\w-]+)"?', line)
        dst = re.search(r'dl_dst=([0-9a-f:]+)', line)
        out_port = re.search(r'output:"?([\w-]+)"?', line)
        pkts = re.search(r'n_packets=(\d+)', line)
        byts = re.search(r'n_bytes=(\d+)', line)
        prio = re.search(r'priority=(\d+)', line)
        rows.append([
            switch,
            in_port.group(1) if in_port else "-",
            dst.group(1) if dst else "-",
            out_port.group(1) if out_port else "-",
            prio.group(1) if prio else "-",
            pkts.group(1) if pkts else "0",
            byts.group(1) if byts else "0",
        ])
    return rows

def print_table(rows):
    headers = ["Switch", "In Port", "Dest MAC", "Out Port", "Priority", "Packets", "Bytes"]
    widths = [max(len(str(r[i])) for r in ([headers] + rows)) for i in range(len(headers))]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-"*w for w in widths]))
    for r in rows:
        print(fmt.format(*r))

if __name__ == "__main__":
    switches = sys.argv[1:] if len(sys.argv) > 1 else ["s0", "s1", "s2"]
    all_rows = []
    for sw in switches:
        all_rows.extend(get_flows(sw))
    print_table(all_rows)
