"use client"

import { useState } from "react"
import {
  LaptopIcon as Linux,
  ComputerIcon as Windows,
  Cloud,
  Network,
  Server,
  Users,
  BarChart,
  Search,
  Shield,
  Box,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import Link from "next/link"

// Mock data for search results
const searchResults = [
  {
    title: "Disable Root SSH Login",
    category: "Linux OS",
    categorySlug: "linux-os",
    icon: Linux,
    description: "Prevent direct root login via SSH to enhance security",
    tags: ["ssh", "configuration", "root", "access control"],
  },
  {
    title: "Harden Windows Firewall",
    category: "Windows OS",
    categorySlug: "windows-os",
    icon: Windows,
    description: "Configure Windows Defender Firewall for improved security",
    tags: ["firewall", "windows", "network", "defender"],
  },
  {
    title: "Secure AWS S3 Buckets",
    category: "Cloud Security",
    categorySlug: "cloud-security",
    icon: Cloud,
    description: "Prevent unauthorized access to S3 storage buckets",
    tags: ["aws", "s3", "storage", "permissions"],
  },
  {
    title: "Network Segmentation Best Practices",
    category: "Networking Architecture",
    categorySlug: "networking-architecture",
    icon: Network,
    description: "Implement proper network segmentation to limit lateral movement",
    tags: ["network", "segmentation", "vlans", "zones"],
  },
  {
    title: "Zero Trust Network Architecture",
    category: "Networking Architecture",
    categorySlug: "networking-architecture",
    icon: Network,
    description: "Implementing zero trust principles in network design",
    tags: ["zero trust", "authentication", "authorization", "micro-segmentation"],
  },
  {
    title: "Tiered Administration Model",
    category: "Active Directory",
    categorySlug: "active-directory",
    icon: Users,
    description: "Implement a tiered administrative model to protect privileged accounts",
    tags: ["active directory", "admin", "tiered model", "privileged access"],
  },
  {
    title: "Secure LDAP Configuration",
    category: "Active Directory",
    categorySlug: "active-directory",
    icon: Users,
    description: "Configure LDAPS and secure LDAP communication",
    tags: ["active directory", "ldap", "ldaps", "encryption"],
  },
  {
    title: "Secure Cisco Router Configuration",
    category: "Network Devices",
    categorySlug: "network-devices",
    icon: Server,
    description: "Harden Cisco routers against common attacks",
    tags: ["cisco", "router", "network", "configuration"],
  },
  {
    title: "Network Switch Hardening",
    category: "Network Devices",
    categorySlug: "network-devices",
    icon: Server,
    description: "Secure network switches with best practices",
    tags: ["switch", "cisco", "juniper", "hardening"],
  },
  {
    title: "Firewall Rule Best Practices",
    category: "Network Devices",
    categorySlug: "network-devices",
    icon: Server,
    description: "Implement effective and secure firewall rules",
    tags: ["firewall", "rules", "acl", "security"],
  },
  {
    title: "Secure Administrative Access",
    category: "Network Devices",
    categorySlug: "network-devices",
    icon: Server,
    description: "Protect administrative access to network devices",
    tags: ["admin", "ssh", "authentication", "access control"],
  },
  {
    title: "Network Device Logging and Monitoring",
    category: "Network Devices",
    categorySlug: "network-devices",
    icon: Server,
    description: "Configure comprehensive logging for network devices",
    tags: ["logging", "syslog", "monitoring", "alerts"],
  },
  {
    title: "Stateful Firewall Implementation",
    category: "Network Security",
    categorySlug: "network-security",
    icon: Shield,
    description: "Configure stateful firewalls to filter traffic based on connection state",
    tags: ["firewall", "stateful", "filtering", "security"],
  },
  {
    title: "IDS/IPS Deployment Strategies",
    category: "Network Security",
    categorySlug: "network-security",
    icon: Shield,
    description: "Implement intrusion detection and prevention systems effectively",
    tags: ["ids", "ips", "intrusion", "detection", "prevention"],
  },
  {
    title: "Secure VPN Configuration",
    category: "Network Security",
    categorySlug: "network-security",
    icon: Shield,
    description: "Set up secure VPN connections for remote access and site-to-site links",
    tags: ["vpn", "remote access", "encryption", "tunneling"],
  },
  {
    title: "TLS Implementation Best Practices",
    category: "Network Security",
    categorySlug: "network-security",
    icon: Shield,
    description: "Configure TLS properly to secure data in transit",
    tags: ["tls", "ssl", "encryption", "certificates"],
  },
  {
    title: "DDoS Protection Strategies",
    category: "Network Security",
    categorySlug: "network-security",
    icon: Shield,
    description: "Implement measures to protect against distributed denial of service attacks",
    tags: ["ddos", "mitigation", "protection", "availability"],
  },
  {
    title: "Secure Docker Container Deployment",
    category: "Virtualization & Containers",
    categorySlug: "virtualization-containers",
    icon: Box,
    description: "Best practices for deploying secure Docker containers",
    tags: ["docker", "containers", "deployment", "security"],
  },
  {
    title: "Kubernetes Security Best Practices",
    category: "Virtualization & Containers",
    categorySlug: "virtualization-containers",
    icon: Box,
    description: "Secure your Kubernetes clusters and workloads",
    tags: ["kubernetes", "k8s", "orchestration", "security"],
  },
  {
    title: "Container Image Security",
    category: "Virtualization & Containers",
    categorySlug: "virtualization-containers",
    icon: Box,
    description: "Build and maintain secure container images",
    tags: ["container", "image", "docker", "security"],
  },
  {
    title: "Hypervisor Hardening",
    category: "Virtualization & Containers",
    categorySlug: "virtualization-containers",
    icon: Box,
    description: "Secure virtualization platforms and hypervisors",
    tags: ["hypervisor", "vmware", "kvm", "virtualization"],
  },
  {
    title: "Kubernetes Network Policies",
    category: "Virtualization & Containers",
    categorySlug: "virtualization-containers",
    icon: Box,
    description: "Implement network segmentation in Kubernetes clusters",
    tags: ["kubernetes", "network", "policy", "segmentation"],
  },
  {
    title: "Centralized Logging Configuration",
    category: "Auditing & Monitoring",
    categorySlug: "auditing-monitoring",
    icon: BarChart,
    description: "Set up centralized logging infrastructure for all systems",
    tags: ["logging", "centralized", "syslog", "aggregation"],
  },
  {
    title: "SIEM Implementation Guide",
    category: "Auditing & Monitoring",
    categorySlug: "auditing-monitoring",
    icon: BarChart,
    description: "Deploy and configure Security Information and Event Management systems",
    tags: ["siem", "security", "monitoring", "correlation"],
  },
  {
    title: "Linux Audit Framework Configuration",
    category: "Auditing & Monitoring",
    categorySlug: "auditing-monitoring",
    icon: BarChart,
    description: "Configure auditd for comprehensive system auditing",
    tags: ["linux", "audit", "auditd", "logging"],
  },
  {
    title: "Windows Event Log Configuration",
    category: "Auditing & Monitoring",
    categorySlug: "auditing-monitoring",
    icon: BarChart,
    description: "Set up comprehensive Windows event logging and forwarding",
    tags: ["windows", "event log", "wef", "monitoring"],
  },
  {
    title: "File Integrity Monitoring Setup",
    category: "Auditing & Monitoring",
    categorySlug: "auditing-monitoring",
    icon: BarChart,
    description: "Implement file integrity monitoring to detect unauthorized changes",
    tags: ["fim", "integrity", "monitoring", "changes"],
  },
  {
    title: "Security Alert Configuration",
    category: "Auditing & Monitoring",
    categorySlug: "auditing-monitoring",
    icon: BarChart,
    description: "Set up effective security alerts to detect suspicious activities",
    tags: ["alerts", "notifications", "detection", "response"],
  },
  {
    title: "Log Retention Policies",
    category: "Auditing & Monitoring",
    categorySlug: "auditing-monitoring",
    icon: BarChart,
    description: "Establish appropriate log retention policies for compliance and security",
    tags: ["retention", "compliance", "logs", "storage"],
  },
  {
    title: "Implement Least Privilege in Active Directory",
    category: "Active Directory",
    categorySlug: "active-directory",
    icon: Users,
    description: "Configure AD permissions following the principle of least privilege",
    tags: ["active directory", "permissions", "least privilege", "access control"],
  },
  {
    title: "Secure Windows 10/11 Configuration",
    category: "Windows OS",
    categorySlug: "windows-os",
    icon: Windows,
    description: "Comprehensive security settings for Windows 10 and 11 workstations",
    tags: ["windows", "configuration", "hardening", "workstation"],
  },
  {
    title: "Windows Server Hardening Checklist",
    category: "Windows OS",
    categorySlug: "windows-os",
    icon: Windows,
    description: "Step-by-step guide to secure Windows Server environments",
    tags: ["windows", "server", "checklist", "hardening"],
  },
  {
    title: "Group Policy Security Settings",
    category: "Windows OS",
    categorySlug: "windows-os",
    icon: Windows,
    description: "Recommended Group Policy settings for enterprise Windows security",
    tags: ["group policy", "gpo", "enterprise", "settings"],
  },
  {
    title: "Azure Security Best Practices",
    category: "Cloud Security",
    categorySlug: "cloud-security",
    icon: Cloud,
    description: "Security hardening for Azure resources and services",
    tags: ["azure", "security", "best practices", "cloud"],
  },
  {
    title: "Google Cloud Security Configuration",
    category: "Cloud Security",
    categorySlug: "cloud-security",
    icon: Cloud,
    description: "Hardening Google Cloud Platform environments",
    tags: ["gcp", "google cloud", "security", "configuration"],
  },
  {
    title: "Active Directory Password Policies",
    category: "Active Directory",
    categorySlug: "active-directory",
    icon: Users,
    description: "Implement strong password policies in Active Directory",
    tags: ["active directory", "password policy", "authentication", "security"],
  },
]

export default function SearchPage() {
  const [searchQuery, setSearchQuery] = useState("")
  const [categoryFilter, setCategoryFilter] = useState("all")
  const [results, setResults] = useState(searchResults)

  // Filter results based on search query and category
  const filterResults = () => {
    return searchResults.filter((result) => {
      const matchesQuery =
        searchQuery === "" ||
        result.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        result.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        result.tags.some((tag) => tag.toLowerCase().includes(searchQuery.toLowerCase()))

      const matchesCategory =
        categoryFilter === "all" || result.category.toLowerCase().includes(categoryFilter.toLowerCase())

      return matchesQuery && matchesCategory
    })
  }

  const handleSearch = () => {
    setResults(filterResults())
  }

  return (
    <div className="container py-8 md:py-12">
      <h1 className="text-3xl font-bold mb-6">Search Security Hardening Resources</h1>

      <div className="grid gap-4 md:grid-cols-4 mb-8">
        <div className="md:col-span-3">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              type="search"
              placeholder="Search for hardening techniques, tools, or configurations..."
              className="pl-8"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            />
          </div>
        </div>
        <div>
          <Select value={categoryFilter} onValueChange={setCategoryFilter}>
            <SelectTrigger>
              <SelectValue placeholder="Filter by category" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Categories</SelectItem>
              <SelectItem value="linux">Linux OS</SelectItem>
              <SelectItem value="windows">Windows OS</SelectItem>
              <SelectItem value="cloud">Cloud Security</SelectItem>
              <SelectItem value="network">Networking</SelectItem>
              <SelectItem value="network security">Network Security</SelectItem>
              <SelectItem value="virtualization">Virtualization & Containers</SelectItem>
              <SelectItem value="auditing">Auditing & Monitoring</SelectItem>
              <SelectItem value="active directory">Active Directory</SelectItem>
              <SelectItem value="network devices">Network Devices</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <Button onClick={handleSearch} className="mb-8">
        Search
      </Button>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {results.map((result, index) => (
          <Link key={index} href={`/category/${result.categorySlug}`} className="block">
            <Card className="h-full transition-colors hover:border-primary">
              <CardHeader className="flex flex-row items-center gap-4">
                <result.icon className="h-6 w-6" />
                <div>
                  <CardTitle className="text-lg">{result.title}</CardTitle>
                  <CardDescription>{result.category}</CardDescription>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-sm">{result.description}</p>
                <div className="flex flex-wrap gap-2 mt-4">
                  {result.tags.map((tag, tagIndex) => (
                    <Badge key={tagIndex} variant="secondary" className="text-xs">
                      {tag}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      {results.length === 0 && (
        <div className="text-center py-12">
          <h2 className="text-xl font-medium mb-2">No results found</h2>
          <p className="text-muted-foreground">Try adjusting your search or filter criteria</p>
        </div>
      )}
    </div>
  )
}
