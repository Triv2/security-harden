import Link from "next/link"
import { ExternalLink, Terminal, Shield, Search, Lock, BarChart, Server, Cloud, Network, Wifi, Users, FileText, Router, Settings } from 'lucide-react'
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"

// Mock data for tools
const tools = [
  {
    name: "Lynis",
    description: "Security auditing tool for Unix/Linux systems",
    category: "Linux",
    url: "https://cisofy.com/lynis/",
    tags: ["scanner", "auditing", "compliance"],
    icon: Terminal,
    usage: "# Run a system audit\nlynis audit system",
  },
  {
    name: "OpenSCAP",
    description: "Suite of tools for compliance and vulnerability scanning",
    category: "Linux",
    url: "https://www.open-scap.org/",
    tags: ["compliance", "scanner", "remediation"],
    icon: Shield,
    usage:
      "# Run a compliance scan\noscap xccdf eval --profile xccdf_org.ssgproject.content_profile_pci-dss --results scan-results.xml /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml",
  },
  {
    name: "Microsoft Baseline Security Analyzer",
    description: "Scans for missing security updates and common security misconfigurations",
    category: "Windows",
    url: "https://www.microsoft.com/en-us/download/details.aspx?id=7558",
    tags: ["scanner", "windows", "updates"],
    icon: Shield,
    usage: "# Run from GUI or command line\nmbsacli.exe /target localhost /n os+iis+sql+password",
  },
  {
    name: "Nessus",
    description: "Vulnerability scanner with extensive plugin library",
    category: "Network",
    url: "https://www.tenable.com/products/nessus",
    tags: ["scanner", "vulnerability", "compliance"],
    icon: Search,
    usage: "# Access via web interface\nhttps://localhost:8834",
  },
  {
    name: "CIS-CAT",
    description: "CIS Configuration Assessment Tool for benchmarking systems",
    category: "Multi-platform",
    url: "https://www.cisecurity.org/tools/cis-cat-pro/",
    tags: ["compliance", "benchmarks", "assessment"],
    icon: Shield,
    usage:
      "# Run assessment\njava -jar CIS-CAT.jar -a -b benchmarks/CIS_Microsoft_Windows_10_Enterprise_Release_1909_Benchmark_v1.8.1-xccdf.xml",
  },
  {
    name: "Fail2ban",
    description: "Intrusion prevention software that protects against brute-force attacks",
    category: "Linux",
    url: "https://www.fail2ban.org/",
    tags: ["intrusion prevention", "brute-force", "protection"],
    icon: Lock,
    usage: "# Check status\nfail2ban-client status\n\n# Check SSH jail status\nfail2ban-client status sshd",
  },
  {
    name: "Wazuh",
    description: "Open source security monitoring solution",
    category: "Multi-platform",
    url: "https://wazuh.com/",
    tags: ["monitoring", "HIDS", "compliance"],
    icon: BarChart,
    usage: "# Check agent status\n/var/ossec/bin/agent_control -l",
  },
  {
    name: "CloudSploit",
    description: "Cloud security configuration monitoring",
    category: "Cloud",
    url: "https://cloudsploit.com/",
    tags: ["cloud", "aws", "azure", "gcp"],
    icon: Cloud,
    usage: "# Run via npm\nnpm install -g cloudsploit\ncloudsploit scan",
  },
  {
    name: "Prowler",
    description: "Open-source security tool for AWS to assess, audit and harden security posture",
    category: "Cloud",
    url: "https://github.com/prowler-cloud/prowler",
    tags: ["aws", "auditing", "compliance", "security"],
    icon: Cloud,
    usage: "# Run Prowler assessment\npip install prowler\nprowler -M csv,json -F /tmp/prowler-output",
  },
  {
    name: "ScoutSuite",
    description: "Multi-cloud security auditing tool that provides a comprehensive security report",
    category: "Cloud",
    url: "https://github.com/nccgroup/ScoutSuite",
    tags: ["multi-cloud", "aws", "azure", "gcp", "auditing"],
    icon: Cloud,
    usage: "# Install and run ScoutSuite\npip install scoutsuite\nscout aws --report-dir /tmp/scout-report",
  },
  {
    name: "Checkov",
    description: "Static code analysis tool for infrastructure-as-code (Terraform, CloudFormation, etc.)",
    category: "Cloud",
    url: "https://github.com/bridgecrewio/checkov",
    tags: ["iac", "terraform", "cloudformation", "static-analysis"],
    icon: Cloud,
    usage: "# Scan Terraform files\npip install checkov\ncheckov -d /path/to/terraform/files",
  },
  {
    name: "Docker Bench for Security",
    description:
      "Script that checks for dozens of common best-practices around deploying Docker containers in production",
    category: "Containers",
    url: "https://github.com/docker/docker-bench-security",
    tags: ["docker", "containers", "security"],
    icon: Server,
    usage: "# Run the script\n./docker-bench-security.sh",
  },
  {
    name: "Windows Security Compliance Toolkit",
    description:
      "Set of tools for downloading, analyzing, testing, and storing Microsoft-recommended security configuration baselines",
    category: "Windows",
    url: "https://www.microsoft.com/en-us/download/details.aspx?id=55319",
    tags: ["compliance", "baselines", "group policy"],
    icon: Shield,
    usage:
      "# Use the included tools:\n# - Policy Analyzer\n# - Local Group Policy Object (LGPO) Tool\n# - Security Compliance Toolkit (SCT)",
  },
  {
    name: "Sysinternals Suite",
    description: "Advanced system utilities for managing, diagnosing, and monitoring Windows systems",
    category: "Windows",
    url: "https://docs.microsoft.com/en-us/sysinternals/",
    tags: ["diagnostics", "monitoring", "utilities"],
    icon: Terminal,
    usage: "# Run Process Explorer\nprocessexplorer.exe\n\n# Run Autoruns to see startup programs\nautoruns.exe",
  },
  {
    name: "Windows Defender Advanced Threat Protection",
    description:
      "Enterprise-level endpoint security platform designed to help detect, prevent, investigate, and respond to advanced threats",
    category: "Windows",
    url: "https://www.microsoft.com/en-us/microsoft-365/windows/microsoft-defender-atp",
    tags: ["endpoint protection", "threat detection", "response"],
    icon: Shield,
    usage: "# Managed through Microsoft 365 Defender portal\nhttps://security.microsoft.com",
  },
  {
    name: "Nmap",
    description: "Network discovery and security auditing tool",
    category: "Network",
    url: "https://nmap.org/",
    tags: ["scanner", "discovery", "port scanning"],
    icon: Network,
    usage:
      "# Basic network scan\nnmap 192.168.1.0/24\n\n# Comprehensive scan with OS detection\nnmap -A -T4 192.168.1.0/24",
  },
  {
    name: "Wireshark",
    description: "Network protocol analyzer for packet capture and inspection",
    category: "Network",
    url: "https://www.wireshark.org/",
    tags: ["packet capture", "analysis", "protocol"],
    icon: Network,
    usage: "# Capture packets on interface eth0\ntshark -i eth0 -w capture.pcap\n\n# Filter traffic by protocol\ntshark -i eth0 -f \"tcp port 80\"",
  },
  {
    name: "pfSense",
    description: "Open source firewall and router platform",
    category: "Network",
    url: "https://www.pfsense.org/",
    tags: ["firewall", "router", "vpn", "security"],
    icon: Shield,
    usage: "# Access via web interface\nhttps://192.168.1.1\n\n# CLI access\nssh admin@192.168.1.1",
  },
  {
    name: "Zeek",
    description: "Network security monitoring tool that provides visibility into network traffic",
    category: "Network",
    url: "https://zeek.org/",
    tags: ["monitoring", "ids", "traffic analysis"],
    icon: Network,
    usage: "# Start Zeek monitoring\nzeek -i eth0\n\n# Analyze specific protocols\nzeek -i eth0 protocols/http",
  },
  {
    name: "Suricata",
    description: "Open source intrusion detection and prevention system",
    category: "Network",
    url: "https://suricata.io/",
    tags: ["ids", "ips", "threat detection"],
    icon: Shield,
    usage:
      "# Run Suricata in IDS mode\nsuricata -c /etc/suricata/suricata.yaml -i eth0\n\n# Check alerts\ntail -f /var/log/suricata/fast.log",
  },
  {
    name: "Aircrack-ng",
    description: "Network software suite for wireless network security assessment",
    category: "Network",
    url: "https://www.aircrack-ng.org/",
    tags: ["wireless", "wifi", "security assessment"],
    icon: Wifi,
    usage:
      "# Put interface in monitor mode\nairmon-ng start wlan0\n\n# Capture handshakes\nairodump-ng -c 1 --bssid [MAC] -w output wlan0mon",
  },
  {
    name: "BloodHound",
    description: "Tool for finding attack paths in Active Directory environments",
    category: "Active Directory",
    url: "https://github.com/BloodHoundAD/BloodHound",
    tags: ["active directory", "attack paths", "privilege escalation"],
    icon: Users,
    usage: "# Run collector (SharpHound)\nImport-Module SharpHound.ps1\nInvoke-BloodHound -CollectionMethod All\n\n# Analyze data in BloodHound UI",
  },
  {
    name: "PingCastle",
    description: "Tool for auditing the security level of Active Directory",
    category: "Active Directory",
    url: "https://www.pingcastle.com/",
    tags: ["active directory", "audit", "security assessment"],
    icon: Users,
    usage: "# Run basic audit\nPingCastle.exe --healthcheck\n\n# Generate report\nPingCastle.exe --healthcheck --server DC01.domain.local --output HTML",
  },
  {
    name: "AD ACL Scanner",
    description: "Tool for creating reports of access control lists in Active Directory",
    category: "Active Directory",
    url: "https://github.com/canix1/ADACLScanner",
    tags: ["active directory", "permissions", "acl", "audit"],
    icon: FileText,
    usage: "# Launch the tool\nADACLScan.ps1\n\n# Scan specific OU\n.\\ADACLScan.ps1 -Base \"OU=Users,DC=domain,DC=local\" -Output HTML -Show",
  },
  {
    name: "Group Policy Management Console",
    description: "Built-in tool for managing Group Policy Objects in Active Directory",
    category: "Active Directory",
    url: "https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn265969(v=ws.11)",
    tags: ["active directory", "group policy", "gpo", "management"],
    icon: FileText,
    usage: "# Launch from PowerShell\ngpmc.msc\n\n# Or from Start Menu\n# Administrative Tools > Group Policy Management",
  },
  {
    name: "Microsoft Advanced Threat Analytics",
    description: "Platform for detecting and investigating advanced attacks and insider threats",
    category: "Active Directory",
    url: "https://docs.microsoft.com/en-us/advanced-threat-analytics/",
    tags: ["active directory", "threat detection", "security", "monitoring"],
    icon: Shield,
    usage: "# Access via web interface\nhttps://ata-center.domain.local\n\n# Review security alerts and suspicious activities",
  },
  {
    name: "Oxidized",
    description: "Tool for network device configuration backup and management",
    category: "Network Devices",
    url: "https://github.com/ytti/oxidized",
    tags: ["configuration", "backup", "management", "network devices"],
    icon: Router,
    usage: "# Install Oxidized\ngem install oxidized\n\n# Configure devices in ~/.config/oxidized/config\n# Start Oxidized\noxidized",
  },
  {
    name: "Rancid",
    description: "Tool for monitoring network device configurations and maintaining history of changes",
    category: "Network Devices",
    url: "https://shrubbery.net/rancid/",
    tags: ["configuration", "backup", "change management", "network devices"],
    icon: Router,
    usage: "# Install Rancid\napt-get install rancid\n\n# Configure devices in /etc/rancid/rancid.conf\n# Run Rancid\nrancid-run",
  },
  {
    name: "Ansible for Network Automation",
    description: "Automation tool for configuring and managing network devices",
    category: "Network Devices",
    url: "https://www.ansible.com/use-cases/network-automation",
    tags: ["automation", "configuration", "management", "network devices"],
    icon: Settings,
    usage: "# Install Ansible\npip install ansible\n\n# Create playbook\n# Run playbook\nansible-playbook -i inventory.ini secure_network.yml",
  },
  {
    name: "Cisco Network Assessment Tool",
    description: "Official Cisco tool for assessing network device security",
    category: "Network Devices",
    url: "https://www.cisco.com/c/en/us/products/security/index.html",
    tags: ["assessment", "cisco", "security", "audit"],
    icon: Shield,
    usage: "# Download from Cisco website\n# Run the assessment tool\njava -jar CiscoNetworkAssessmentTool.jar",
  },
  {
    name: "Netmiko",
    description: "Python library for connecting to network devices via SSH",
    category: "Network Devices",
    url: "https://github.com/ktbyers/netmiko",
    tags: ["automation", "ssh", "python", "network devices"],
    icon: Terminal,
    usage: "# Install Netmiko\npip install netmiko\n\n# Python script to connect and run commands\nfrom netmiko import ConnectHandler\n\ndevice = {\n    'device_type': 'cisco_ios',\n    'host': '192.168.1.1',\n    'username': 'admin',\n    'password': 'password',\n}",
  },
]

export default function ToolsPage() {
  return (
    <div className="container py-8 md:py-12">
      <h1 className="text-3xl font-bold mb-2">Security Hardening Tools</h1>
      <p className="text-muted-foreground mb-8">
        A curated collection of tools for system hardening and security assessment
      </p>

      <Tabs defaultValue="all" className="mb-8">
        <TabsList>
          <TabsTrigger value="all">All Tools</TabsTrigger>
          <TabsTrigger value="Linux">Linux</TabsTrigger>
          <TabsTrigger value="Windows">Windows</TabsTrigger>
          <TabsTrigger value="Network">Network</TabsTrigger>
          <TabsTrigger value="Cloud">Cloud</TabsTrigger>
          <TabsTrigger value="Active Directory">Active Directory</TabsTrigger>
          <TabsTrigger value="Network Devices">Network Devices</TabsTrigger>
          <TabsTrigger value="Containers">Containers</TabsTrigger>
          <TabsTrigger value="Multi-platform">Multi-platform</TabsTrigger>
        </TabsList>

        {["all", "Linux", "Windows", "Network", "Cloud", "Active Directory", "Network Devices", "Containers", "Multi-platform"].map((category) => (
          <TabsContent key={category} value={category} className="mt-6">
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
              {tools
                .filter((tool) => category === "all" || tool.category === category)
                .map((tool, index) => (
                  <Card key={index} className="h-full flex flex-col">
                    <CardHeader>
                      <div className="flex items-start justify-between">
                        <div className="flex items-center gap-2">
                          <tool.icon className="h-5 w-5" />
                          <CardTitle>{tool.name}</CardTitle>
                        </div>
                        <Badge>{tool.category}</Badge>
                      </div>
                      <CardDescription>{tool.description}</CardDescription>
                    </CardHeader>
                    <CardContent className="flex-grow">
                      <div className="flex flex-wrap gap-2 mb-4">
                        {tool.tags.map((tag, tagIndex) => (
                          <Badge key={tagIndex} variant="outline" className="text-xs">
                            {tag}
                          </Badge>
                        ))}
                      </div>
                      <div className="bg-muted p-3 rounded-md text-xs overflow-x-auto">
                        <pre>{tool.usage}</pre>
                      </div>
                    </CardContent>
                    <CardFooter>
                      <a
                        href={tool.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center text-sm text-primary hover:underline"
                      >
                        Visit Website
                        <ExternalLink className="ml-1 h-3 w-3" />
                      </a>
                    </CardFooter>
                  </Card>
                ))}
            </div>

            {tools.filter((tool) => category === "all" || tool.category === category).length === 0 && (
              <div className="text-center py-12">
                <h2 className="text-xl font-medium mb-2">No tools found</h2>
                <p className="text-muted-foreground">No tools available for this category</p>
              </div>
            )}
          </TabsContent>
        ))}
      </Tabs>

      <div className="bg-muted p-6 rounded-lg">
        <h2 className="text-xl font-bold mb-4">Suggest a Tool</h2>
        <p className="mb-4">Know a great security hardening tool that should be included here? Let us know!</p>
        <Button>
          <Link
            href="https://github.com/yourusername/security-hardening-tool/issues/new"
            target="_blank"
            rel="noopener noreferrer"
          >
            Suggest Tool
          </Link>
        </Button>
      </div>
    </div>
  )
}

