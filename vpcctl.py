#!/usr/bin/env python3
import argparse
import json
import subprocess
from pathlib import Path
import time
import ipaddress
import shlex
import hashlib
import logging



# Directory to store VPC states
STATE_DIR = Path.home() / ".vpcctl"
STATE_DIR.mkdir(parents=True, exist_ok=True)

# Directory to store per-function logs in the same directory as the script
SCRIPT_DIR = Path(__file__).parent.resolve()
LOGS_DIR = SCRIPT_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = STATE_DIR / "vpcctl.log"

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

def write_func_log(func_name, content):
    """Write log content to .logs/<funcname>.log"""
    log_path = LOGS_DIR / f"{func_name}.log"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(content + "\n")

def run(cmd, check=True, capture_output=False, text=True):
    """Run a shell command, log it, and return CompletedProcess."""
    if isinstance(cmd, (list, tuple)):
        printable = " ".join(shlex.quote(str(x)) for x in cmd)
    else:
        printable = str(cmd)
    log(f"[CMD] {printable}", "info")
    result = subprocess.run(cmd, check=check, capture_output=capture_output, text=text)
    if result.returncode == 0:
        log(f"[OK] Command succeeded: {printable}", "info")
    else:
        log(f"[FAIL] Command failed ({result.returncode}): {printable}", "error")
    return result

def run_ok(cmd):
    """Run command and return True on success."""
    r = run(cmd, check=False, capture_output=True)
    return r.returncode == 0

def log(msg, level="info"):
    """Log to both console and file with timestamp."""
    print(msg)
    if level.lower() == "error":
        logging.error(msg)
    elif level.lower() == "warn" or level.lower() == "warning":
        logging.warning(msg)
    else:
        logging.info(msg)

def save_state(vpc_name, data):
    """Save VPC metadata to disk."""
    with open(STATE_DIR / f"{vpc_name}.json", "w") as f:
        json.dump(data, f, indent=2)

def load_state(vpc_name):
    """Load VPC metadata from disk."""
    path = STATE_DIR / f"{vpc_name}.json"
    if not path.exists():
        print(f"[ERROR] VPC '{vpc_name}' not found.")
        exit(1)
    with open(path) as f:
        return json.load(f)

def delete_state(vpc_name):
    """Delete a saved VPC metadata file."""
    path = STATE_DIR / f"{vpc_name}.json"
    if path.exists():
        path.unlink()

def iface_exists(name):
    r = run(["ip", "link", "show", name], check=False, capture_output=True)
    return r.returncode == 0

def ns_exists(name):
    r = run(["ip", "netns", "list"], check=True, capture_output=True)
    return name in r.stdout

def ip_addr_on_dev(dev, ip_with_mask):
    r = run(["ip", "addr", "show", "dev", dev], check=False, capture_output=True)
    return ip_with_mask.split('/')[0] in r.stdout

def ensure_iptables_chain(chain):
    rc = run(["iptables", "-n", "-L", chain], check=False, capture_output=True)
    if rc.returncode != 0:
        run(["iptables", "-N", chain])
    if run(["iptables", "-C", "FORWARD", "-j", chain], check=False, capture_output=True).returncode != 0:
        run(["iptables", "-A", "FORWARD", "-j", chain])

def map_action(action):
    a = action.strip().lower()
    if a in ("allow", "accept", "ac", "a"):
        return "ACCEPT"
    if a in ("deny", "drop", "reject", "d"):
        return "DROP"
    if a.upper() in ("ACCEPT", "DROP"):
        return a.upper()
    raise ValueError(f"Unknown action: {action}")

def _short_hash(*parts, length=6):
    s = ":".join(parts)
    return hashlib.sha1(s.encode()).hexdigest()[:length]

def veth_names_for_subnet(vpc_name, subnet_name):
    h = _short_hash(vpc_name, subnet_name)
    veth_ns = f"veth{h}n"
    veth_host = f"veth{h}h"
    return veth_ns, veth_host

def peer_veth_names(vpc1, vpc2):
    h = _short_hash(vpc1, vpc2)
    return f"pv{h}a", f"pv{h}b"

def create_vpc(args):
    vpc_name = args.name
    cidr = args.cidr
    bridge = f"{vpc_name}-lb"

    print(f"[INFO] Creating VPC '{vpc_name}' with CIDR {cidr}")

    # Create bridge if not exists
    if not iface_exists(bridge):
        run(["ip", "link", "add", bridge, "type", "bridge"])
    else:
        print(f"[WARN] Bridge {bridge} already exists, skipping creation.")

    # Bring bridge up
    run(["ip", "link", "set", bridge, "up"])

    # Enable kernel IP forwarding
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    chain = f"vpc-{vpc_name}"
    ensure_iptables_chain(chain)

    vpc_data = {
        "name": vpc_name,
        "cidr": cidr,
        "bridge": bridge,
        "subnets": {}
    }
    save_state(vpc_name, vpc_data)

    print(f"[SUCCESS] VPC '{vpc_name}' created successfully.")
    # Per-function log
    log_content = f"Created VPC '{vpc_name}' with CIDR {cidr} and bridge {bridge}"
    write_func_log("createvpc", log_content)

def add_subnet(args):
    vpc_name = args.vpc
    subnet_name = args.name
    cidr = args.cidr

    vpc_data = load_state(vpc_name)
    bridge = vpc_data["bridge"]

    ns_name = f"ns-{vpc_name}-{subnet_name}"
    veth_ns, veth_host = veth_names_for_subnet(vpc_name, subnet_name)

    print(f"[INFO] Creating subnet '{subnet_name}' with CIDR {cidr}")

    net = ipaddress.ip_network(cidr)
    hosts = list(net.hosts())
    if len(hosts) < 2:
        print(f"[ERROR] CIDR {cidr} is too small to allocate hosts")
        return
    gw = str(hosts[0])
    host_ip = str(hosts[1])
    mask = net.prefixlen

    # Clean up veth interfaces if either already exists
    for iface in (veth_ns, veth_host):
        if iface_exists(iface):
            print(f"[WARN] Interface '{iface}' exists. Removing it first.")
            run(["ip", "link", "del", iface], check=False)

    # Clean up namespace if it exists (and may have veth stuck in it)
    if ns_exists(ns_name):
        ip_links = run(["ip", "netns", "exec", ns_name, "ip", "link"], check=False, capture_output=True)
        if veth_ns in ip_links.stdout:
            print(f"[WARN] Removing old namespace '{ns_name}' containing stuck veth.")
            run(["ip", "netns", "del", ns_name], check=False)

    # Create namespace
    if not ns_exists(ns_name):
        run(["ip", "netns", "add", ns_name])
    else:
        print(f"[WARN] Namespace {ns_name} already exists.")

    # Always create veth pair fresh
    run(["ip", "link", "add", veth_ns, "type", "veth", "peer", "name", veth_host])

    # Configure veths and netns
    run(["ip", "link", "set", veth_ns, "netns", ns_name])
    run(["ip", "netns", "exec", ns_name, "ip", "link", "set", "lo", "up"])
    run(["ip", "netns", "exec", ns_name, "ip", "addr", "add", f"{host_ip}/{mask}", "dev", veth_ns], check=False)
    run(["ip", "netns", "exec", ns_name, "ip", "link", "set", veth_ns, "up"])

    bridge_addr = f"{gw}/{mask}"
    if not ip_addr_on_dev(bridge, bridge_addr):
        run(["ip", "addr", "add", bridge_addr, "dev", bridge], check=False)

    run(["ip", "link", "set", veth_host, "up"])
    run(["ip", "link", "set", veth_host, "master", bridge], check=False)
    run(["ip", "netns", "exec", ns_name, "ip", "route", "replace", "default", "via", gw], check=False)
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    vpc_data["subnets"][subnet_name] = {
        "namespace": ns_name,
        "veth_ns": veth_ns,
        "veth_host": veth_host,
        "cidr": cidr,
        "gateway": gw,
        "host_ip": host_ip
    }
    save_state(vpc_name, vpc_data)

    print(f"[SUCCESS] Subnet '{subnet_name}' created and attached to VPC '{vpc_name}'.")
    # Per-function log
    log_content = f"Added subnet '{subnet_name}' with CIDR {cidr} to VPC '{vpc_name}'"
    write_func_log("addsubnet", log_content)

def deploy_app(args):
    vpc_name = args.vpc
    subnet_name = args.subnet
    port = args.port
    vpc_data = load_state(vpc_name)
    if subnet_name not in vpc_data["subnets"]:
        print(f"[ERROR] Subnet '{subnet_name}' not found in VPC '{vpc_name}'.")
        return
    ns_name = vpc_data["subnets"][subnet_name]["namespace"]
    print(f"[INFO] Deploying HTTP server in namespace '{ns_name}' on port {port}...")
    log_file = f"/tmp/{ns_name.replace('/', '_')}-{port}.log"
    cmd = ["ip", "netns", "exec", ns_name, "python3", "-m", "http.server", str(port)]
    f = open(log_file, "w")
    process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
    pid = process.pid
    if "apps" not in vpc_data["subnets"][subnet_name]:
        vpc_data["subnets"][subnet_name]["apps"] = {}
    vpc_data["subnets"][subnet_name]["apps"][str(port)] = {
        "pid": pid,
        "cmd": cmd,
        "log": log_file
    }
    save_state(vpc_name, vpc_data)

    print(f"[SUCCESS] HTTP server deployed in '{subnet_name}' on port {port} (PID: {pid}).")
    print(f"[INFO] Logs available at {log_file}")
    # Per-function log
    log_content = f"Deployed HTTP server in subnet '{subnet_name}' of VPC '{vpc_name}' on port {port} (PID: {pid})"
    write_func_log("deployapp", log_content)


def stop_app(args):
    vpc_name = args.vpc
    subnet_name = args.subnet

    vpc_data = load_state(vpc_name)
    if subnet_name not in vpc_data["subnets"]:
        print(f"[ERROR] Subnet '{subnet_name}' not found in VPC '{vpc_name}'.")
        return

    subnet_data = vpc_data["subnets"][subnet_name]
    apps = subnet_data.get("apps", {})
    if not apps:
        print(f"[INFO] No apps deployed in subnet '{subnet_name}'.")
        return

    for port, app in list(apps.items()):
        pid = app.get("pid")
        if not pid:
            continue
        print(f"[INFO] Stopping app on port {port} (PID: {pid})...")
        try:
            run(["kill", "-TERM", str(pid)], check=False)
            time.sleep(2)
            if run_ok(["kill", "-0", str(pid)]):
                print(f"[WARN] PID {pid} did not terminate, sending SIGKILL...")
                run(["kill", "-KILL", str(pid)], check=False)
        except Exception:
            pass
        print(f"[SUCCESS] App on port {port} stopped.")
        del apps[port]  # ✅ FIXED


    save_state(vpc_name, vpc_data)
    # Per-function log
    log_content = f"Stopped all apps in subnet '{subnet_name}' of VPC '{vpc_name}'"
    write_func_log("stopapp", log_content)


def enable_nat(args):
    vpc_name = args.vpc
    internet_iface = args.internet_iface
    vpc_data = load_state(vpc_name)
    bridge = vpc_data["bridge"]
    vpc_cidr = vpc_data["cidr"]
    print(f"[INFO] Enabling NAT for VPC '{vpc_name}' via host interface '{internet_iface}'")
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    if run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", vpc_cidr, "-o", internet_iface, "-j", "MASQUERADE"], check=False).returncode != 0:
        run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", vpc_cidr, "-o", internet_iface, "-j", "MASQUERADE"])
    if run(["iptables", "-C", "FORWARD", "-i", bridge, "-o", internet_iface, "-j", "ACCEPT"], check=False).returncode != 0:
        run(["iptables", "-A", "FORWARD", "-i", bridge, "-o", internet_iface, "-j", "ACCEPT"])
    if run(["iptables", "-C", "FORWARD", "-i", internet_iface, "-o", bridge, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=False).returncode != 0:
        run(["iptables", "-A", "FORWARD", "-i", internet_iface, "-o", bridge, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])

    print(f"[SUCCESS] NAT enabled for VPC '{vpc_name}'. Public subnets can now reach the internet.")
    # Per-function log
    log_content = f"Enabled NAT for VPC '{vpc_name}' via interface '{internet_iface}'"
    write_func_log("enablenat", log_content)

def peer_vpcs(args):
    vpc1 = args.vpc
    vpc2 = args.other_vpc
    allowed_cidrs = [c.strip() for c in args.allow_cidrs.split(",") if c.strip()]
    vpc1_data = load_state(vpc1)
    vpc2_data = load_state(vpc2)
    br1 = vpc1_data["bridge"]
    br2 = vpc2_data["bridge"]
    veth1, veth2 = peer_veth_names(vpc1, vpc2)
    if not iface_exists(veth1) and not iface_exists(veth2):
        run(["ip", "link", "add", veth1, "type", "veth", "peer", "name", veth2])
        run(["ip", "link", "set", veth1, "master", br1])
        run(["ip", "link", "set", veth2, "master", br2])
        run(["ip", "link", "set", veth1, "up"])
        run(["ip", "link", "set", veth2, "up"])
        print(f"[SUCCESS] VPCs '{vpc1}' and '{vpc2}' bridged via veth pair.")
    else:
        print(f"[WARN] Peering veth pair {veth1}<->{veth2} already exists.")
    for i in range(0, len(allowed_cidrs), 2):
        try:
            cidr1 = allowed_cidrs[i]
            cidr2 = allowed_cidrs[i + 1]
        except IndexError:
            print(f"[WARN] Ignoring unmatched CIDR entry at position {i}")
            break
        run(["iptables", "-C", f"vpc-{vpc1}", "-s", cidr1, "-d", cidr2, "-j", "ACCEPT"], check=False)
        run(["iptables", "-A", f"vpc-{vpc1}", "-s", cidr1, "-d", cidr2, "-j", "ACCEPT"], check=False)
        run(["iptables", "-C", f"vpc-{vpc2}", "-s", cidr2, "-d", cidr1, "-j", "ACCEPT"], check=False)
        run(["iptables", "-A", f"vpc-{vpc2}", "-s", cidr2, "-d", cidr1, "-j", "ACCEPT"], check=False)

    print(f"[INFO] Allowed CIDR pairs configured: {allowed_cidrs}")
    # Per-function log
    log_content = f"Peered VPCs '{vpc1}' and '{vpc2}' with allowed CIDR pairs: {allowed_cidrs}"
    write_func_log("peervpcs", log_content)

def apply_policy(args):
    vpc_name = args.vpc
    policy_file = Path(args.policy_file)
    if not policy_file.exists():
        print(f"[ERROR] Policy file '{policy_file}' does not exist.")
        return
    vpc_data = load_state(vpc_name)
    with open(policy_file) as f:
        policy = json.load(f)
    subnet_name = policy.get("subnet")
    if subnet_name not in vpc_data["subnets"]:
        print(f"[ERROR] Subnet '{subnet_name}' not found in VPC '{vpc_name}'.")
        return
    ns_name = vpc_data["subnets"][subnet_name]["namespace"]
    def apply_rule(chain, rule):
        port = str(rule["port"])
        proto = rule.get("protocol", "tcp")
        action = map_action(rule["action"])
        comment_tag = f"vpcctl:{action.lower()}-{port}"
        base_cmd = [
            "ip", "netns", "exec", ns_name,
            "iptables", "-C", chain, "-p", proto, "--dport", port, "-j", action
        ]
        result = run(base_cmd, check=False, capture_output=True)
        if result.returncode != 0:
            run([
                "ip", "netns", "exec", ns_name,
                "iptables", "-A", chain, "-p", proto, "--dport", port,
                "-j", action, "-m", "comment", "--comment", comment_tag
            ], check=False)
            print(f"[INFO] Applied {action} rule for port {port} in {ns_name}")
        else:
            print(f"[INFO] Rule for port {port} already exists in {ns_name}, skipping.")
    for r in policy.get("ingress", []):
        apply_rule("INPUT", r)
    for r in policy.get("egress", []):
        apply_rule("OUTPUT", r)

    print(f"[SUCCESS] Policy applied to subnet '{subnet_name}' in VPC '{vpc_name}'.")
    # Per-function log
    log_content = f"Applied policy from '{policy_file}' to subnet '{subnet_name}' in VPC '{vpc_name}'"
    write_func_log("applypolicy", log_content)

def inspect_vpc(args):

    vpc_data = load_state(args.name)
    print(json.dumps(vpc_data, indent=2))
    # Per-function log
    log_content = f"Inspected VPC '{args.name}'"
    write_func_log("inspectvpc", log_content)

def delete_vpc(args):
    vpc_name = args.name
    data = load_state(vpc_name)
    bridge = data["bridge"]
    print(f"[INFO] Deleting VPC '{vpc_name}' and bridge '{bridge}'")
    run(["ip", "link", "set", bridge, "down"], check=False)
    run(["ip", "link", "del", bridge], check=False)
    for subnet_name in list(data["subnets"].keys()):
        try:
            stop_app(argparse.Namespace(vpc=vpc_name, subnet=subnet_name))
        except Exception:
            pass
    run(["iptables", "-F", f"vpc-{vpc_name}"], check=False)
    run(["iptables", "-X", f"vpc-{vpc_name}"], check=False)
    for subnet, info in data["subnets"].items():
        ns = info.get("namespace")
        if ns:
            run(["ip", "netns", "del", ns], check=False)
    delete_state(vpc_name)

    print(f"[SUCCESS] VPC '{vpc_name}' deleted successfully.")
    # Per-function log
    log_content = f"Deleted VPC '{vpc_name}' and bridge '{bridge}'"
    write_func_log("deletevpc", log_content)

def list_vpcs(args):
    files = list(STATE_DIR.glob("*.json"))
    if not files:
        print("[INFO] No VPCs found.")
        return

    for f in files:
        with open(f) as fh:
            data = json.load(fh)
            bridge = data.get("bridge", "N/A")
            print(f"- {data.get('name', 'unknown')} ({data.get('cidr', 'unknown')}) [Bridge: {bridge}]")
    # Per-function log
    log_content = f"Listed VPCs: {[f.stem for f in files]}"
    write_func_log("listvpcs", log_content)

def main():
    parser = argparse.ArgumentParser(prog="vpcctl", description="Mini VPC Manager")
    sub = parser.add_subparsers(dest="command", required=True)
    create_cmd = sub.add_parser("create", help="Create a VPC")
    create_cmd.add_argument("--name", required=True)
    create_cmd.add_argument("--cidr", required=True)
    create_cmd.set_defaults(func=create_vpc)
    subnet_cmd = sub.add_parser("add-subnet", help="Add subnet")
    subnet_cmd.add_argument("--vpc", required=True)
    subnet_cmd.add_argument("--name", required=True)
    subnet_cmd.add_argument("--cidr", required=True)
    subnet_cmd.set_defaults(func=add_subnet)
    deploy_parser = sub.add_parser("deploy-app", help="Deploy a simple HTTP app in a subnet")
    deploy_parser.add_argument("--vpc", required=True)
    deploy_parser.add_argument("--subnet", required=True)
    deploy_parser.add_argument("--port", type=int, required=True)
    deploy_parser.set_defaults(func=deploy_app)
    stop_parser = sub.add_parser("stop-app", help="Stop HTTP apps in a subnet")
    stop_parser.add_argument("--vpc", required=True)
    stop_parser.add_argument("--subnet", required=True)
    stop_parser.set_defaults(func=stop_app)
    nat_cmd = sub.add_parser("enable-nat", help="Enable NAT")
    nat_cmd.add_argument("--vpc", required=True)
    nat_cmd.add_argument("--internet-iface", required=True)
    nat_cmd.set_defaults(func=enable_nat)
    peer_parser = sub.add_parser("peer", help="Peer two VPCs with restricted CIDR ranges")
    peer_parser.add_argument("--vpc", required=True)
    peer_parser.add_argument("--other-vpc", required=True)
    peer_parser.add_argument(
        "--allow-cidrs", required=True,
        help="Comma-separated list of allowed CIDR pairs (vpc1_cidr,vpc2_cidr,...)"
    )
    peer_parser.set_defaults(func=peer_vpcs)
    policy_parser = sub.add_parser(
        "apply-policy",
        help="Apply JSON-defined ingress/egress rules to a subnet namespace"
    )
    policy_parser.add_argument("--vpc", required=True)
    policy_parser.add_argument(
        "policy_file", help="Path to JSON policy file"
    )
    policy_parser.set_defaults(func=apply_policy)
    delete_cmd = sub.add_parser("delete", help="Delete a VPC")
    delete_cmd.add_argument("--name", required=True)
    delete_cmd.set_defaults(func=delete_vpc)

    inspect_cmd = sub.add_parser("inspect", help="Inspect a VPC's details")
    inspect_cmd.add_argument("--name", required=True)
    inspect_cmd.set_defaults(func=inspect_vpc)
    list_cmd = sub.add_parser("list", help="List VPCs")
    list_cmd.set_defaults(func=list_vpcs)
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()

