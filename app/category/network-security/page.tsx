"use client"

import Link from "next/link"
import { ChevronRight, Copy, ExternalLink, Shield, AlertTriangle, BookOpen, Lock, Eye, Zap, Server } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

// Network Security category data
const networkSecurity = {
  title: "Network Security Controls",
  tagline: "Implement firewalls, IDS/IPS, and other security controls to protect your network",
  icon: Shield,
  overview:
    "Network security involves implementing controls to protect the confidentiality, integrity, and availability of network infrastructure and data. This guide covers essential security technologies, implementation strategies, and best practices for securing network traffic and preventing unauthorized access and attacks.",
  bestPractices: [
    {
      title: "Implement Stateful Firewalls",
      description: "Deploy stateful firewalls to filter traffic based on connection state and application awareness.",
      command: `# Example iptables stateful firewall rules
# Allow established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow new SSH connections from specific subnet
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# Allow new HTTP/HTTPS connections from anywhere
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Drop all other incoming traffic
iptables -A INPUT -j DROP`,
    },
    {
      title: "Deploy Intrusion Detection/Prevention Systems",
      description: "Implement IDS/IPS to detect and block malicious traffic patterns and attack signatures.",
      command: `# Example Snort IDS configuration (snort.conf)
# Set network variables
ipvar HOME_NET 192.168.1.0/24
ipvar EXTERNAL_NET !$HOME_NET

# Set rule path
var RULE_PATH /etc/snort/rules

# Configure detection engine
config detection: search-method ac-bnfa max_pattern_len 20000 

# Include rules
include $RULE_PATH/local.rules
include $RULE_PATH/attack-responses.rules
include $RULE_PATH/backdoor.rules
include $RULE_PATH/bad-traffic.rules
include $RULE_PATH/exploit.rules

# Example rule to detect SSH brute force
# In local.rules:
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"INDICATOR-SCAN SSH brute force login attempt"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000001; rev:1;)`,
    },
    {
      title: "Secure Remote Access with VPN",
      description: "Use VPNs to encrypt remote access connections and protect sensitive data in transit.",
      command: `# Example OpenVPN server configuration (server.conf)
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 208.67.222.222"
push "dhcp-option DNS 208.67.220.220"
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-CBC
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3`,
    },
    {
      title: "Implement Network Access Control",
      description: "Use NAC to enforce security policies for devices connecting to your network.",
      command: `# Example 802.1X configuration for Cisco switch
# Global configuration
aaa new-model
radius server RADIUS-SERVER
 address ipv4 192.168.1.100 auth-port 1812 acct-port 1813
 key StrongSharedSecret

aaa group server radius RADIUS-GROUP
 server name RADIUS-SERVER

aaa authentication dot1x default group RADIUS-GROUP
aaa authorization network default group RADIUS-GROUP

dot1x system-auth-control

# Interface configuration
interface GigabitEthernet1/0/1
 switchport access vlan 10
 switchport mode access
 authentication port-control auto
 dot1x pae authenticator
 spanning-tree portfast`,
    },
    {
      title: "Implement TLS for Secure Communications",
      description:
        "Use TLS to encrypt data in transit and protect against eavesdropping and man-in-the-middle attacks.",
      command: `# Example Nginx HTTPS configuration
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate /etc/nginx/ssl/example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.key;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # HSTS (15768000 seconds = 6 months)
    add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload";
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Diffie-Hellman parameters
    ssl_dhparam /etc/nginx/ssl/dhparam.pem;
    
    # Other security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    
    # Rest of your configuration
    location / {
        proxy_pass http://backend;
        # ...
    }
}`,
    },
    {
      title: "Implement DDoS Protection",
      description: "Deploy DDoS mitigation solutions to protect against volumetric and application-layer attacks.",
      command: `# Example iptables rate limiting rules
# Limit SYN packets to mitigate SYN flood
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Limit ICMP packets
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Limit new connections per source IP
iptables -A INPUT -p tcp -m state --state NEW -m recent --set
iptables -A INPUT -p tcp -m state --state NEW -m recent --update --seconds 60 --hitcount 20 -j DROP

# Example Nginx rate limiting
# In nginx.conf:
http {
    # Define limit zones
    limit_req_zone $binary_remote_addr zone=ip:10m rate=1r/s;
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    server {
        # Apply rate limiting to specific locations
        location /login {
            limit_req zone=ip burst=5 nodelay;
            limit_conn addr 10;
            # ...
        }
    }
}`,
    },
  ],
  tools: [
    {
      name: "pfSense",
      description: "Open source firewall and router platform with extensive security features",
      usage: `# Access via web interface
https://192.168.1.1

# CLI access
ssh admin@192.168.1.1

# View firewall logs
tail -f /var/log/filter.log`,
    },
    {
      name: "Snort",
      description: "Open source network intrusion detection and prevention system",
      usage: `# Run Snort in IDS mode
snort -c /etc/snort/snort.conf -i eth0 -A console

# Run Snort in IPS mode
snort -c /etc/snort/snort.conf -i eth0 -A console -Q --daq afpacket -i eth0:eth1

# Test a rule
snort -c /etc/snort/snort.conf -T`,
    },
    {
      name: "Suricata",
      description: "High performance network IDS, IPS and network security monitoring engine",
      usage: `# Run Suricata in IDS mode
suricata -c /etc/suricata/suricata.yaml -i eth0

# Check alerts
tail -f /var/log/suricata/fast.log

# Update rules
suricata-update`,
    },
    {
      name: "OpenVPN",
      description: "Open source VPN solution for secure remote access and site-to-site connections",
      usage: `# Start OpenVPN server
openvpn --config /etc/openvpn/server.conf

# Connect as client
openvpn --config client.ovpn

# Check connection status
systemctl status openvpn@server`,
    },
    {
      name: "WireGuard",
      description: "Simple, fast, and modern VPN with state-of-the-art cryptography",
      usage: `# Start WireGuard interface
wg-quick up wg0

# Check connection status
wg show

# Stop WireGuard interface
wg-quick down wg0`,
    },
    {
      name: "Fail2ban",
      description: "Intrusion prevention software that protects against brute-force attacks",
      usage: `# Check status
fail2ban-client status

# Check SSH jail status
fail2ban-client status sshd

# Unban an IP
fail2ban-client set sshd unbanip 192.168.1.100`,
    },
    {
      name: "ModSecurity",
      description: "Web application firewall for protecting web applications from attacks",
      usage: `# Check ModSecurity status in Apache
apachectl -M | grep security

# Test configuration
apachectl configtest

# View ModSecurity logs
tail -f /var/log/apache2/modsec_audit.log`,
    },
    {
      name: "Wireshark",
      description: "Network protocol analyzer for packet capture and inspection",
      usage: `# Capture packets on interface eth0
tshark -i eth0 -w capture.pcap

# Filter traffic by protocol
tshark -i eth0 -f "tcp port 80"

# Analyze captured traffic
wireshark capture.pcap`,
    },
  ],
  pitfalls: [
    "Implementing perimeter security without defense in depth",
    "Relying solely on firewalls without additional security controls",
    "Using default or weak credentials for network devices and security appliances",
    "Failing to regularly update and patch security devices and their signatures",
    "Implementing overly permissive firewall rules or security policies",
    "Not monitoring security logs and alerts from network security devices",
    "Neglecting to test security controls and conduct regular security assessments",
    "Implementing security solutions without proper planning and understanding",
    "Not having incident response procedures for security breaches",
    "Forgetting to secure management interfaces and protocols",
  ],
  references: [
    {
      title: "NIST SP 800-41: Guidelines on Firewalls and Firewall Policy",
      url: "https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final",
    },
    {
      title: "NIST SP 800-94: Guide to Intrusion Detection and Prevention Systems",
      url: "https://csrc.nist.gov/publications/detail/sp/800-94/final",
    },
    {
      title: "NIST SP 800-77: Guide to IPsec VPNs",
      url: "https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final",
    },
    {
      title: "SANS Network Security Checklist",
      url: "https://www.sans.org/security-resources/policies/network-security/pdf/network-security-policy",
    },
    {
      title: "OWASP Transport Layer Protection Cheat Sheet",
      url: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
    },
  ],
}

export default function NetworkSecurityPage() {
  const { title, tagline, icon: Icon, overview, bestPractices, tools, pitfalls, references } = networkSecurity

  return (
    <div className="container py-8 md:py-12">
      <div className="flex items-center gap-1 text-sm text-muted-foreground mb-6">
        <Link href="/" className="hover:text-foreground">
          Home
        </Link>
        <ChevronRight className="h-4 w-4" />
        <span>Category</span>
        <ChevronRight className="h-4 w-4" />
        <span className="text-foreground">{title}</span>
      </div>

      <div className="flex flex-col md:flex-row gap-8">
        <div className="md:w-3/4">
          <div className="flex items-center gap-4 mb-6">
            <div className="bg-muted p-3 rounded-lg">
              <Icon className="h-8 w-8" />
            </div>
            <div>
              <h1 className="text-3xl font-bold">{title}</h1>
              <p className="text-muted-foreground">{tagline}</p>
            </div>
          </div>

          <Tabs defaultValue="overview" className="mb-8">
            <TabsList className="grid w-full grid-cols-3 md:grid-cols-6">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="best-practices">Best Practices</TabsTrigger>
              <TabsTrigger value="tools">Tools</TabsTrigger>
              <TabsTrigger value="examples">Examples</TabsTrigger>
              <TabsTrigger value="pitfalls">Pitfalls</TabsTrigger>
              <TabsTrigger value="references">References</TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle>Overview</CardTitle>
                  <CardDescription>Understanding network security fundamentals</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>{overview}</p>

                  <div className="grid gap-4 md:grid-cols-3">
                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Shield className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Perimeter Security</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Implement firewalls, gateways, and other border controls to filter traffic entering and
                          leaving your network.
                        </p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Eye className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Threat Detection</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Deploy IDS/IPS systems to identify and respond to suspicious activities and known attack
                          patterns.
                        </p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Lock className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Secure Communications</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Use encryption protocols like TLS and VPNs to protect data in transit from eavesdropping and
                          tampering.
                        </p>
                      </CardContent>
                    </Card>
                  </div>

                  <Alert>
                    <Zap className="h-4 w-4" />
                    <AlertTitle>Defense in Depth</AlertTitle>
                    <AlertDescription>
                      Network security should be implemented in layers. Don't rely on a single security control to
                      protect your entire network. Combine multiple technologies and approaches for comprehensive
                      protection.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="best-practices" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle>Best Practices</CardTitle>
                  <CardDescription>Essential security configurations for network protection</CardDescription>
                </CardHeader>
                <CardContent>
                  <Accordion type="single" collapsible className="w-full">
                    {bestPractices.map((practice, index) => (
                      <AccordionItem key={index} value={`item-${index}`}>
                        <AccordionTrigger>{practice.title}</AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-4">
                            <p>{practice.description}</p>
                            <div className="relative">
                              <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                                <code>{practice.command}</code>
                              </pre>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="absolute top-2 right-2"
                                onClick={() => navigator.clipboard.writeText(practice.command)}
                              >
                                <Copy className="h-4 w-4" />
                                <span className="sr-only">Copy code</span>
                              </Button>
                            </div>
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                    ))}
                  </Accordion>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="tools" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle>Essential Tools</CardTitle>
                  <CardDescription>Software to help implement and manage network security</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-6 md:grid-cols-2">
                    {tools.map((tool, index) => (
                      <Card key={index} className="border">
                        <CardHeader>
                          <CardTitle className="text-lg">{tool.name}</CardTitle>
                          <CardDescription>{tool.description}</CardDescription>
                        </CardHeader>
                        <CardContent>
                          <div className="relative">
                            <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                              <code>{tool.usage}</code>
                            </pre>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="absolute top-2 right-2"
                              onClick={() => navigator.clipboard.writeText(tool.usage)}
                            >
                              <Copy className="h-4 w-4" />
                              <span className="sr-only">Copy code</span>
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="examples" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle>Configuration Examples</CardTitle>
                  <CardDescription>Sample configurations for common network security controls</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <h3 className="text-lg font-medium mb-2">Advanced Firewall Configuration (iptables)</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`#!/bin/bash
# Reset iptables
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from specific network
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# Allow HTTP and HTTPS
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Allow DNS queries
iptables -A INPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# Allow ICMP echo-request (ping)
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4

# Save rules
iptables-save > /etc/iptables/rules.v4`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`#!/bin/bash
# Reset iptables
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from specific network
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# Allow HTTP and HTTPS
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Allow DNS queries
iptables -A INPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# Allow ICMP echo-request (ping)
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4

# Save rules
iptables-save > /etc/iptables/rules.v4`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">Site-to-Site VPN Configuration (OpenVPN)</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# Server configuration (server.conf)
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "route 192.168.1.0 255.255.255.0"
client-config-dir ccd
route 192.168.2.0 255.255.255.0
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-GCM
auth SHA256
compress lz4-v2
push "compress lz4-v2"
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3

# Client configuration (client.ovpn)
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
tls-auth ta.key 1
cipher AES-256-GCM
auth SHA256
compress lz4-v2
verb 3`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# Server configuration (server.conf)
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "route 192.168.1.0 255.255.255.0"
client-config-dir ccd
route 192.168.2.0 255.255.255.0
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-GCM
auth SHA256
compress lz4-v2
push "compress lz4-v2"
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3

# Client configuration (client.ovpn)
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
tls-auth ta.key 1
cipher AES-256-GCM
auth SHA256
compress lz4-v2
verb 3`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">IDS/IPS Configuration (Suricata)</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# Excerpt from suricata.yaml
%YAML 1.1
---
# Suricata configuration file

vars:
  # Define home networks
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    
  # Define HTTP ports
  port-groups:
    HTTP_PORTS: "80"
    HTTPS_PORTS: "443"
    
# Configure detection engine
detect-engine:
  # Select the detection mode
  - profile: medium
  # Set the inspection limits
  inspection-recursion-limit: 3000
  
# Configure outputs
outputs:
  # Fast log for alerts
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  
  # Detailed logs in EVE JSON format
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - ssh
        
# Configure rules
default-rule-path: /etc/suricata/rules
rule-files:
  - suricata.rules
  - local.rules
  - emerging-attack_response.rules
  - emerging-exploit.rules
  - emerging-malware.rules
  - emerging-scan.rules
  - emerging-web_client.rules
  - emerging-web_server.rules

# Example custom rule in local.rules
# alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Potential SSH Brute Force"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1  threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000001; rev:1;)"

# Configure network capture
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# Excerpt from suricata.yaml
%YAML 1.1
---
# Suricata configuration file

vars:
  # Define home networks
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    
  # Define HTTP ports
  port-groups:
    HTTP_PORTS: "80"
    HTTPS_PORTS: "443"
    
# Configure detection engine
detect-engine:
  # Select the detection mode
  - profile: medium
  # Set the inspection limits
  inspection-recursion-limit: 3000
  
# Configure outputs
outputs:
  # Fast log for alerts
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  
  # Detailed logs in EVE JSON format
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - ssh
        
# Configure rules
default-rule-path: /etc/suricata/rules
rule-files:
  - suricata.rules
  - local.rules
  - emerging-attack_response.rules
  - emerging-exploit.rules
  - emerging-malware.rules
  - emerging-scan.rules
  - emerging-web_client.rules
  - emerging-web_server.rules

# Example custom rule in local.rules
# alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Potential SSH Brute Force"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000001; rev:1;)

# Configure network capture
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">Web Application Firewall Configuration (ModSecurity)</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# ModSecurity configuration for Apache (modsecurity.conf)
# Enable ModSecurity
SecRuleEngine On

# Request body access
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyInMemoryLimit 131072
SecRequestBodyLimitAction Reject

# Response body access
SecResponseBodyAccess On
SecResponseBodyLimit 1048576
SecResponseBodyLimitAction ProcessPartial

# File uploads handling
SecUploadDir /tmp
SecUploadKeepFiles Off
SecUploadFileMode 0600

# Debug log
SecDebugLog /var/log/apache2/modsec_debug.log
SecDebugLogLevel 0

# Audit log
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/apache2/modsec_audit.log

# Include OWASP Core Rule Set
Include /etc/modsecurity/owasp-crs/crs-setup.conf
Include /etc/modsecurity/owasp-crs/rules/*.conf

# Custom rules
# Block SQL injection attempts
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|REQUEST_HEADERS|REQUEST_HEADERS_NAMES|REQUEST_BODY|REQUEST_LINE|ARGS|ARGS_NAMES "(?i:(?:select\\s+(?:concat|char|hex)\\s*\\(|(?:union|and|or)\\s+select|into\\s+(?:dump|out)file\\s*\\(?|group\\s+by.+?having|like\\s*\\(?\\s*\\(?|procedure\\s+analyse\\s*\\(|from\\s+information_schema|;\\s*(?:drop|alter|create)\\s+(?:table|database|procedure)))" \
    "id:1000,phase:2,deny,status:403,log,msg:'SQL Injection Attempt'"

# Block XSS attempts
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|REQUEST_HEADERS|REQUEST_HEADERS_NAMES|REQUEST_BODY|REQUEST_LINE|ARGS|ARGS_NAMES "(?i:<script[^>]*>|<[^>]*\\bon\\w+\\s*=|(?:javascript|vbscript|expression|data)\\s*:)" \
    "id:1001,phase:2,deny,status:403,log,msg:'XSS Attempt'"

# Block path traversal attempts
SecRule REQUEST_URI|REQUEST_HEADERS|ARGS|ARGS_NAMES "(?:\\.\\.[\\/\\\\]|[\\/\\\\]\\.\\.)" \
    "id:1002,phase:2,deny,status:403,log,msg:'Directory Traversal Attempt'"`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# ModSecurity configuration for Apache (modsecurity.conf)
# Enable ModSecurity
SecRuleEngine On

# Request body access
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyInMemoryLimit 131072
SecRequestBodyLimitAction Reject

# Response body access
SecResponseBodyAccess On
SecResponseBodyLimit 1048576
SecResponseBodyLimitAction ProcessPartial

# File uploads handling
SecUploadDir /tmp
SecUploadKeepFiles Off
SecUploadFileMode 0600

# Debug log
SecDebugLog /var/log/apache2/modsec_debug.log
SecDebugLogLevel 0

# Audit log
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/apache2/modsec_audit.log

# Include OWASP Core Rule Set
Include /etc/modsecurity/owasp-crs/crs-setup.conf
Include /etc/modsecurity/owasp-crs/rules/*.conf

# Custom rules
# Block SQL injection attempts
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|REQUEST_HEADERS|REQUEST_HEADERS_NAMES|REQUEST_BODY|REQUEST_LINE|ARGS|ARGS_NAMES "(?i:(?:select\\s+(?:concat|char|hex)\\s*\\(|(?:union|and|or)\\s+select|into\\s+(?:dump|out)file\\s*\\(?|group\\s+by.+?having|like\\s*\\(?\\s*\\(?|procedure\\s+analyse\\s*\\(|from\\s+information_schema|;\\s*(?:drop|alter|create)\\s+(?:table|database|procedure)))" \
    "id:1000,phase:2,deny,status:403,log,msg:'SQL Injection Attempt'"

# Block XSS attempts
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|REQUEST_HEADERS|REQUEST_HEADERS_NAMES|REQUEST_BODY|REQUEST_LINE|ARGS|ARGS_NAMES "(?i:<script[^>]*>|<[^>]*\\bon\\w+\\s*=|(?:javascript|vbscript|expression|data)\\s*:)" \
    "id:1001,phase:2,deny,status:403,log,msg:'XSS Attempt'"

# Block path traversal attempts
SecRule REQUEST_URI|REQUEST_HEADERS|ARGS|ARGS_NAMES "(?:\\.\\.[\\/\\\\]|[\\/\\\\]\\.\\.)" \
    "id:1002,phase:2,deny,status:403,log,msg:'Directory Traversal Attempt'"`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="pitfalls" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle>Common Pitfalls</CardTitle>
                  <CardDescription>Mistakes to avoid when implementing network security</CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-4">
                    {pitfalls.map((pitfall, index) => (
                      <li key={index} className="flex items-start gap-2">
                        <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5 flex-shrink-0" />
                        <span>{pitfall}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="references" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle>External References</CardTitle>
                  <CardDescription>Additional resources and documentation</CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-4">
                    {references.map((reference, index) => (
                      <li key={index} className="flex items-start gap-2">
                        <BookOpen className="h-5 w-5 text-primary mt-0.5 flex-shrink-0" />
                        <a
                          href={reference.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 hover:underline"
                        >
                          {reference.title}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>

        <div className="md:w-1/4">
          <div className="sticky top-24">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">On This Page</CardTitle>
              </CardHeader>
              <CardContent>
                <nav className="space-y-1">
                  <a href="#overview" className="block text-sm hover:underline">
                    Overview
                  </a>
                  <a href="#best-practices" className="block text-sm hover:underline">
                    Best Practices
                  </a>
                  <a href="#tools" className="block text-sm hover:underline">
                    Essential Tools
                  </a>
                  <a href="#examples" className="block text-sm hover:underline">
                    Configuration Examples
                  </a>
                  <a href="#pitfalls" className="block text-sm hover:underline">
                    Common Pitfalls
                  </a>
                  <a href="#references" className="block text-sm hover:underline">
                    External References
                  </a>
                </nav>
              </CardContent>
            </Card>

            <Card className="mt-6">
              <CardHeader>
                <CardTitle className="text-lg">Related Categories</CardTitle>
              </CardHeader>
              <CardContent>
                <nav className="space-y-1">
                  <Link href="/category/networking-architecture" className="block text-sm hover:underline">
                    Networking Architecture
                  </Link>
                  <Link href="/category/network-devices" className="block text-sm hover:underline">
                    Network Devices
                  </Link>
                  <Link href="/category/auditing-monitoring" className="block text-sm hover:underline">
                    Auditing & Monitoring
                  </Link>
                </nav>
              </CardContent>
            </Card>

            <Alert className="mt-6">
              <Server className="h-4 w-4" />
              <AlertTitle>Regular Updates</AlertTitle>
              <AlertDescription className="text-sm">
                Keep your network security tools and signatures updated regularly. New vulnerabilities and attack
                techniques emerge constantly, and outdated security controls may not provide adequate protection.
              </AlertDescription>
            </Alert>
          </div>
        </div>
      </div>
    </div>
  )
}

