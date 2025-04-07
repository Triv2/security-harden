"use client"

import Link from "next/link"
import {
  ChevronRight,
  Copy,
  ExternalLink,
  Shield,
  AlertTriangle,
  BookOpen,
  Network,
  Lock,
  Layers,
  Wifi,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

// Network Architecture category data
const networkArchitecture = {
  title: "Network Architecture Security",
  tagline: "Design secure network infrastructure with proper segmentation and defense in depth",
  icon: Network,
  overview:
    "Secure network architecture is the foundation of organizational security. It involves designing networks with security in mind from the ground up, implementing proper segmentation, and following defense-in-depth principles. This guide covers essential network security design patterns, segmentation strategies, and implementation techniques.",
  bestPractices: [
    {
      title: "Implement Network Segmentation",
      description: "Divide networks into isolated segments to limit lateral movement and contain breaches.",
      command: `# Example Cisco configuration for VLANs
! Create VLANs
vlan 10
 name Corporate
vlan 20
 name Guest
vlan 30
 name IoT
vlan 40
 name Security

! Configure trunk ports
interface GigabitEthernet1/0/1
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30,40

! Configure access ports
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 10`,
    },
    {
      title: "Deploy Defense in Depth",
      description: "Implement multiple layers of security controls throughout the network.",
      command: `# Example pfSense firewall rules (CLI)
# Block all traffic by default
block in all
block out all

# Allow established connections
pass in quick proto tcp from any to any established
pass out quick proto tcp from any to any established

# Allow specific services
pass in on $ext_if proto tcp from any to $webserver port 443 keep state
pass in on $ext_if proto tcp from any to $mailserver port {25, 587, 993} keep state`,
    },
    {
      title: "Secure Network Perimeter",
      description: "Implement strong border controls with firewalls, IDS/IPS, and DMZ.",
      command: `# Example iptables DMZ configuration
# Allow traffic to DMZ web server
iptables -A FORWARD -i eth0 -o eth1 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

# Allow traffic to DMZ mail server
iptables -A FORWARD -i eth0 -o eth1 -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -p tcp --sport 25 -m state --state ESTABLISHED -j ACCEPT

# Block all other traffic to internal network
iptables -A FORWARD -i eth0 -o eth2 -j DROP`,
    },
    {
      title: "Implement Zero Trust Architecture",
      description: "Verify every access request regardless of source location.",
      command: `# Example configuration for identity-aware proxy (conceptual)
# 1. Configure authentication
auth:
  provider: oauth2
  oauth2:
    clientID: "your-client-id"
    clientSecret: "your-client-secret"
    authURL: "https://auth.example.com/authorize"
    tokenURL: "https://auth.example.com/token"
    
# 2. Configure authorization policies
policies:
  - name: "internal-apps"
    resources:
      - "https://app1.internal.example.com/*"
      - "https://app2.internal.example.com/*"
    conditions:
      groups:
        - "employees"
      networkConditions:
        - "corporate-network"
      deviceConditions:
        - "managed-devices"`,
    },
    {
      title: "Secure Wireless Networks",
      description: "Implement strong encryption, authentication, and segmentation for wireless networks.",
      command: `# Example WPA2-Enterprise configuration (hostapd.conf)
interface=wlan0
driver=nl80211
ssid=SecureEnterprise
hw_mode=g
channel=6
ieee8021x=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
auth_server_addr=192.168.1.10
auth_server_port=1812
auth_server_shared_secret=your_radius_secret`,
    },
  ],
  tools: [
    {
      name: "Nmap",
      description: "Network discovery and security auditing tool",
      usage: `# Basic network scan
nmap 192.168.1.0/24

# Comprehensive scan with OS detection
nmap -A -T4 192.168.1.0/24

# Scan for specific vulnerabilities
nmap --script vuln 192.168.1.100`,
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
    {
      name: "pfSense",
      description: "Open source firewall and router platform",
      usage: `# Access via web interface
https://192.168.1.1

# CLI access
ssh admin@192.168.1.1

# View firewall logs
tail -f /var/log/filter.log`,
    },
    {
      name: "Zeek (formerly Bro)",
      description: "Network security monitoring tool that provides visibility into network traffic",
      usage: `# Start Zeek monitoring
zeek -i eth0

# Analyze specific protocols
zeek -i eth0 protocols/http

# Generate logs
zeek -i eth0 local`,
    },
    {
      name: "OpenVAS",
      description: "Open source vulnerability scanner and manager",
      usage: `# Start OpenVAS
openvas-start

# Run a vulnerability scan
omp -u admin -w password -C -n "Network Scan" --target=192.168.1.0/24

# Generate report
omp -u admin -w password -R`,
    },
    {
      name: "Suricata",
      description: "Open source intrusion detection and prevention system",
      usage: `# Run Suricata in IDS mode
suricata -c /etc/suricata/suricata.yaml -i eth0

# Check alerts
tail -f /var/log/suricata/fast.log

# Update rules
suricata-update`,
    },
  ],
  pitfalls: [
    "Implementing flat networks without proper segmentation",
    "Relying solely on perimeter security (firewall) without internal controls",
    "Using outdated or weak encryption protocols for network traffic",
    "Failing to monitor network traffic for suspicious activities",
    "Neglecting to secure management interfaces and protocols",
    "Implementing overly complex network designs that are difficult to maintain",
    "Not documenting network architecture and security controls",
    "Forgetting to segment IoT devices from critical infrastructure",
  ],
  references: [
    {
      title: "NIST SP 800-53: Security and Privacy Controls",
      url: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    },
    {
      title: "NIST SP 800-207: Zero Trust Architecture",
      url: "https://csrc.nist.gov/publications/detail/sp/800-207/final",
    },
    {
      title: "Cisco Network Segmentation Design Guide",
      url: "https://www.cisco.com/c/en/us/td/docs/solutions/Enterprise/Security/Segmentation/segmentation_guide.html",
    },
    {
      title: "NSA Network Infrastructure Security Guide",
      url: "https://www.nsa.gov/portals/75/documents/what-we-do/cybersecurity/professional-resources/csi-network-infrastructure-security-guide.pdf",
    },
    {
      title: "SANS Network Security Checklist",
      url: "https://www.sans.org/security-resources/policies/network-security/pdf/network-security-policy",
    },
  ],
}

export default function NetworkArchitecturePage() {
  const { title, tagline, icon: Icon, overview, bestPractices, tools, pitfalls, references } = networkArchitecture

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
                  <CardDescription>Understanding network security architecture fundamentals</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>{overview}</p>

                  <div className="grid gap-4 md:grid-cols-3">
                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Layers className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Segmentation</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Divide networks into isolated segments based on security requirements, trust levels, and
                          functional needs to limit the impact of breaches.
                        </p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Shield className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Defense in Depth</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Implement multiple layers of security controls throughout the network to provide redundancy if
                          one layer is compromised.
                        </p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Lock className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Zero Trust</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Never trust, always verify. Authenticate and authorize every access request regardless of
                          source location.
                        </p>
                      </CardContent>
                    </Card>
                  </div>

                  <Alert>
                    <Shield className="h-4 w-4" />
                    <AlertTitle>Security by Design</AlertTitle>
                    <AlertDescription>
                      Network security should be built into the architecture from the beginning, not added as an
                      afterthought. Consider security implications at every stage of network design.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="best-practices" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle>Best Practices</CardTitle>
                  <CardDescription>Essential security configurations for network architecture</CardDescription>
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
                  <CardDescription>Software to help design, implement, and secure network architecture</CardDescription>
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
                  <CardDescription>Sample configurations for secure network architecture</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <h3 className="text-lg font-medium mb-2">Network Segmentation with VLANs and ACLs</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`! Cisco Switch Configuration
! Create VLANs
vlan 10
 name Corporate
vlan 20
 name Guest
vlan 30
 name IoT
vlan 40
 name Security

! Configure SVI interfaces
interface Vlan10
 ip address 10.1.10.1 255.255.255.0
 ip helper-address 10.1.1.10
 no ip redirects
 no ip unreachables

interface Vlan20
 ip address 10.1.20.1 255.255.255.0
 ip access-group GUEST_ACL in
 no ip redirects
 no ip unreachables

! Configure ACLs
ip access-list extended GUEST_ACL
 permit tcp any any eq 80
 permit tcp any any eq 443
 permit udp any any eq 53
 deny   ip any 10.1.10.0 0.0.0.255
 deny   ip any 10.1.30.0 0.0.0.255
 deny   ip any 10.1.40.0 0.0.0.255
 permit ip any any`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`! Cisco Switch Configuration
! Create VLANs
vlan 10
 name Corporate
vlan 20
 name Guest
vlan 30
 name IoT
vlan 40
 name Security

! Configure SVI interfaces
interface Vlan10
 ip address 10.1.10.1 255.255.255.0
 ip helper-address 10.1.1.10
 no ip redirects
 no ip unreachables

interface Vlan20
 ip address 10.1.20.1 255.255.255.0
 ip access-group GUEST_ACL in
 no ip redirects
 no ip unreachables

! Configure ACLs
ip access-list extended GUEST_ACL
 permit tcp any any eq 80
 permit tcp any any eq 443
 permit udp any any eq 53
 deny   ip any 10.1.10.0 0.0.0.255
 deny   ip any 10.1.30.0 0.0.0.255
 deny   ip any 10.1.40.0 0.0.0.255
 permit ip any any`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">DMZ Configuration with Firewall Rules</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# pfSense Firewall Rules (conceptual)

# WAN Interface Rules
# Block all incoming traffic by default
block in on WAN all

# Allow established connections
pass in on WAN proto tcp from any to any established

# Allow specific services to DMZ
pass in on WAN proto tcp from any to DMZ_NET port 80 flags S/SA keep state
pass in on WAN proto tcp from any to DMZ_NET port 443 flags S/SA keep state
pass in on WAN proto tcp from any to DMZ_NET port 25 flags S/SA keep state

# DMZ Interface Rules
# Block DMZ to LAN by default
block in on DMZ all

# Allow specific services from DMZ to LAN
pass in on DMZ proto tcp from DMZ_NET to LAN_NET port 3306 flags S/SA keep state
pass in on DMZ proto tcp from DMZ_NET to LAN_NET port 1433 flags S/SA keep state

# LAN Interface Rules
# Allow all outbound traffic from LAN
pass out on LAN all keep state

# Allow specific services from LAN to DMZ
pass in on LAN proto tcp from LAN_NET to DMZ_NET port 80 flags S/SA keep state
pass in on LAN proto tcp from LAN_NET to DMZ_NET port 443 flags S/SA keep state`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# pfSense Firewall Rules (conceptual)

# WAN Interface Rules
# Block all incoming traffic by default
block in on WAN all

# Allow established connections
pass in on WAN proto tcp from any to any established

# Allow specific services to DMZ
pass in on WAN proto tcp from any to DMZ_NET port 80 flags S/SA keep state
pass in on WAN proto tcp from any to DMZ_NET port 443 flags S/SA keep state
pass in on WAN proto tcp from any to DMZ_NET port 25 flags S/SA keep state

# DMZ Interface Rules
# Block DMZ to LAN by default
block in on DMZ all

# Allow specific services from DMZ to LAN
pass in on DMZ proto tcp from DMZ_NET to LAN_NET port 3306 flags S/SA keep state
pass in on DMZ proto tcp from DMZ_NET to LAN_NET port 1433 flags S/SA keep state

# LAN Interface Rules
# Allow all outbound traffic from LAN
pass out on LAN all keep state

# Allow specific services from LAN to DMZ
pass in on LAN proto tcp from LAN_NET to DMZ_NET port 80 flags S/SA keep state
pass in on LAN proto tcp from LAN_NET to DMZ_NET port 443 flags S/SA keep state`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">Secure Wireless Network Configuration</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# hostapd.conf for WPA2-Enterprise

interface=wlan0
driver=nl80211
ssid=SecureEnterprise
hw_mode=g
channel=6
wmm_enabled=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
rsn_pairwise=CCMP
ieee8021x=1

# RADIUS server settings
auth_server_addr=192.168.1.10
auth_server_port=1812
auth_server_shared_secret=your_radius_secret
acct_server_addr=192.168.1.10
acct_server_port=1813
acct_server_shared_secret=your_radius_secret

# Additional security settings
macaddr_acl=1
accept_mac_file=/etc/hostapd/allowed_macs
ignore_broadcast_ssid=1
wpa_group_rekey=600
wpa_gmk_rekey=86400
wpa_ptk_rekey=600
ieee80211w=2  # Management frame protection required`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# hostapd.conf for WPA2-Enterprise

interface=wlan0
driver=nl80211
ssid=SecureEnterprise
hw_mode=g
channel=6
wmm_enabled=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
rsn_pairwise=CCMP
ieee8021x=1

# RADIUS server settings
auth_server_addr=192.168.1.10
auth_server_port=1812
auth_server_shared_secret=your_radius_secret
acct_server_addr=192.168.1.10
acct_server_port=1813
acct_server_shared_secret=your_radius_secret

# Additional security settings
macaddr_acl=1
accept_mac_file=/etc/hostapd/allowed_macs
ignore_broadcast_ssid=1
wpa_group_rekey=600
wpa_gmk_rekey=86400
wpa_ptk_rekey=600
ieee80211w=2  # Management frame protection required`)
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
                  <CardDescription>Mistakes to avoid when designing network architecture</CardDescription>
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
                  <Link href="/category/network-security" className="block text-sm hover:underline">
                    Network Security
                  </Link>
                  <Link href="/category/network-devices" className="block text-sm hover:underline">
                    Network Devices
                  </Link>
                  <Link href="/category/cloud-security" className="block text-sm hover:underline">
                    Cloud Security
                  </Link>
                </nav>
              </CardContent>
            </Card>

            <Alert className="mt-6">
              <Wifi className="h-4 w-4" />
              <AlertTitle>Network Diagram</AlertTitle>
              <AlertDescription className="text-sm">
                Always maintain up-to-date network diagrams that document segmentation, security controls, and data
                flows.
              </AlertDescription>
            </Alert>
          </div>
        </div>
      </div>
    </div>
  )
}

