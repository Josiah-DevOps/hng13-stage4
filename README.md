
vpcctl – Mini Virtual Private Cloud (VPC) on Linux
 
A lightweight VPC CLI tool that allows you to create isolated virtual networks, subnets, NAT gateways, peering, and firewall policies entirely on a Linux host using network namespaces, veth pairs, bridges, and iptables.
________________________________________
Table of Contents
1.	Overview
2.	Architecture
3.	Installation
4.	CLI Usage
5.	Testing & Validation
6.	Firewall Policies
7.	Cleanup
________________________________________
Overview
vpcctl enables you to simulate real cloud VPC features locally:
•	Create multiple VPCs with unique CIDRs
•	Add public/private subnets
•	Enable NAT gateway for outbound internet access
•	Isolate VPCs by default, optionally connect via peering
•	Apply firewall rules using JSON policies
•	Deploy simple HTTP servers to test connectivity
This is ideal for learning Linux networking, isolation, routing, and DevOps networking automation.
________________________________________
Architecture
             Internet (via host)
                   |
             +-------------+
             |   Bridge    |  <- VPC router
             +-------------+
              |      |
          veth-h   veth-h
             |      |
        +--------+ +--------+
        |  NS    | |  NS    | <- Subnets (public/private)
        +--------+ +--------+
        |  App   | |  App   | <- HTTP servers
        +--------+ +--------+
Components:
•	Bridge: acts as VPC router
•	Namespaces (NS): subnets
•	Veth pairs: connect subnets to bridge
•	iptables: NAT & firewall enforcement
________________________________________
Installation
1.	Clone the repository:
git clone https://github.com/<username>/vpcctl.git
cd vpcctl
2.	Ensure Python 3 is installed
python3 --version
3.	Make CLI executable (optional)
chmod +x vpcctl.py
All commands should be run with sudo to manipulate network interfaces.
________________________________________
CLI Usage
Create a VPC
sudo python3 vpcctl.py create --name vpc1 --cidr 10.0.0.0/16
Add Subnets
Public Subnet (with NAT access)
sudo python3 vpcctl.py add-subnet --vpc vpc1 --name public --cidr 10.0.1.0/24
Private Subnet (internal-only)
sudo python3 vpcctl.py add-subnet --vpc vpc1 --name private --cidr 10.0.2.0/24
Deploy HTTP Server
sudo python3 vpcctl.py deploy-app --vpc vpc1 --subnet public --port 8080
Stop HTTP Server
sudo python3 vpcctl.py stop-app --vpc vpc1 --subnet public
Enable NAT Gateway
sudo python3 vpcctl.py enable-nat --vpc vpc1 --internet-iface eth0
Peer Two VPCs
sudo python3 vpcctl.py peer --vpc vpc1 --other-vpc vpc2 --allow-cidrs 10.0.1.0/24,10.1.1.0/24
Apply Firewall Policy
sudo python3 vpcctl.py apply-policy --vpc vpc1 policies/example_policy.json
Delete a VPC
sudo python3 vpcctl.py delete --name vpc1
List VPCs
sudo python3 vpcctl.py list
________________________________________
Testing & Validation
1. Subnet Communication (Same VPC)
sudo ip netns exec ns-vpc1-public ping -c 2 10.0.2.1
 Should succeed
2. NAT / Internet Access
•	Public subnet can ping external IPs (e.g., 8.8.8.8)
•	Private subnet cannot reach external IPs
3. VPC Isolation
•	Ping between subnets in different VPCs → fails
•	After peering → succeeds for allowed CIDRs only
4. Firewall Enforcement
•	Apply JSON rules
•	Test with curl or telnet to verify access
5. Logs
•	[INFO] and [SUCCESS] messages show all VPC actions
•	App logs saved under /tmp/ns-<subnet>-<port>.log
________________________________________
Firewall Policies
Policies are defined in JSON:
{
  "subnet": "10.0.1.0/24",
  "ingress": [
    {"port": 80, "protocol": "tcp", "action": "allow"},
    {"port": 22, "protocol": "tcp", "action": "deny"}
  ],
  "egress": [
    {"port": 443, "protocol": "tcp", "action": "allow"}
  ]
}
•	ingress: incoming traffic
•	egress: outgoing traffic
•	action: allow or deny
________________________________________
Cleanup
Remove all VPCs, namespaces, bridges, and iptables chains:
sudo bash cleanup.sh
Ensures a clean environment
________________________________________

