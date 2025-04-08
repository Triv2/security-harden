"use client"

import Link from "next/link"
import { ChevronRight, Copy, ExternalLink, LaptopIcon as Linux, Shield, AlertTriangle, BookOpen } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

// Linux OS specific data
const category = {
  title: "Linux Operating System Hardening",
  tagline: "Secure your Linux servers and workstations against common threats",
  icon: Linux,
  overview:
    "Linux systems are known for their security, but proper hardening is essential to minimize vulnerabilities. This guide covers essential configurations, best practices, and tools to secure your Linux environment.",
  bestPractices: [
    {
      title: "Minimize installed packages",
      description: "Only install necessary software to reduce the attack surface.",
      command: "# List all installed packages\ndpkg -l    # Debian/Ubuntu\nrpm -qa    # RHEL/CentOS",
    },
    {
      title: "Secure user accounts",
      description: "Implement strong password policies and restrict access to privileged accounts.",
      command:
        "# Set password complexity requirements\nvim /etc/security/pwquality.conf\n\n# Restrict su command to wheel group\nvim /etc/pam.d/su",
    },
    {
      title: "Configure SSH properly",
      description: "Disable root login, use key-based authentication, and limit access.",
      command:
        "# Edit SSH configuration\nvim /etc/ssh/sshd_config\n\n# Key settings to change:\nPermitRootLogin no\nPasswordAuthentication no\nX11Forwarding no\nAllowUsers user1 user2",
    },
    {
      title: "Enable and configure firewall",
      description: "Use iptables, nftables, or ufw to restrict network access.",
      command:
        "# Enable UFW (Ubuntu)\nufw default deny incoming\nufw default allow outgoing\nufw allow ssh\nufw enable\n\n# Check status\nufw status verbose",
    },
  ],
  tools: [
    {
      name: "Lynis",
      description: "Security auditing tool for Unix/Linux systems",
      usage: "# Run a system audit\nlynis audit system",
    },
    {
      name: "ClamAV",
      description: "Open-source antivirus engine for detecting trojans, viruses, and malware",
      usage: "# Update virus definitions\nfreshclam\n\n# Scan a directory\nclamscan -r /path/to/directory",
    },
    {
      name: "Fail2ban",
      description: "Intrusion prevention software that protects against brute-force attacks",
      usage: "# Check status\nfail2ban-client status\n\n# Check SSH jail status\nfail2ban-client status sshd",
    },
  ],
  pitfalls: [
    "Forgetting to keep the system updated with security patches",
    "Using weak or default passwords for user accounts",
    "Leaving unnecessary services running",
    "Not monitoring system logs for suspicious activity",
    "Failing to implement proper backup strategies",
  ],
  references: [
    {
      title: "CIS Linux Benchmarks",
      url: "https://www.cisecurity.org/benchmark/linux",
    },
    {
      title: "NIST SP 800-123",
      url: "https://csrc.nist.gov/publications/detail/sp/800-123/final",
    },
    {
      title: "Linux Security Checklist",
      url: "https://linuxsecurity.expert/checklists/linux-security-checklist/",
    },
  ],
}

export default function LinuxOSPage() {
  const { title, tagline, icon: Icon, overview, bestPractices, tools, pitfalls, references } = category

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
                  <CardDescription>Understanding Linux security fundamentals</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>{overview}</p>

                  <Alert>
                    <Shield className="h-4 w-4" />
                    <AlertTitle>Security First</AlertTitle>
                    <AlertDescription>
                      Always test hardening measures in a non-production environment before implementing them on
                      critical systems.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="best-practices" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle>Best Practices</CardTitle>
                  <CardDescription>Essential security configurations for Linux systems</CardDescription>
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
                  <CardDescription>Software to help secure and audit Linux systems</CardDescription>
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
                  <CardDescription>Sample configurations for common security controls</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <h3 className="text-lg font-medium mb-2">Secure SSH Configuration</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          # /etc/ssh/sshd_config Protocol 2 PermitRootLogin no PasswordAuthentication no
                          PubkeyAuthentication yes PermitEmptyPasswords no X11Forwarding no MaxAuthTries 3
                          ClientAliveInterval 300 ClientAliveCountMax 0 AllowUsers user1 user2 # Restart SSH service
                          after changes systemctl restart sshd
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# /etc/ssh/sshd_config
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 0
AllowUsers user1 user2

# Restart SSH service after changes
systemctl restart sshd`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">Basic Firewall Rules</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          # UFW (Ubuntu) ufw default deny incoming ufw default allow outgoing ufw allow ssh ufw allow
                          http ufw allow https ufw enable # Check status ufw status verbose
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# UFW (Ubuntu)
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw enable

# Check status
ufw status verbose`)
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
                  <CardDescription>Mistakes to avoid when hardening Linux systems</CardDescription>
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
                  <CardDescription>Additional resources and cheatsheets</CardDescription>
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
                  <Link href="/windows-os" className="block text-sm hover:underline">
                    Windows OS Hardening
                  </Link>
                  <Link href="/category/network-security" className="block text-sm hover:underline">
                    Network Security
                  </Link>
                  <Link href="/category/auditing-monitoring" className="block text-sm hover:underline">
                    Auditing & Monitoring
                  </Link>
                  <Link href="/category/virtualization-containers" className="block text-sm hover:underline">
                    Virtualization & Containers
                  </Link>
                </nav>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}
