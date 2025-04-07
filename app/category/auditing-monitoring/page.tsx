"use client"

import Link from "next/link"
import {
  ChevronRight,
  Copy,
  ExternalLink,
  Shield,
  AlertTriangle,
  BookOpen,
  BarChart,
  Bell,
  Search,
  FileText,
  Clock,
  Database,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

// Auditing & Monitoring category data
const auditingMonitoring = {
  title: "Auditing & Monitoring",
  tagline: "Track system activities and detect security incidents",
  icon: BarChart,
  overview:
    "Effective security auditing and monitoring are essential for detecting, investigating, and responding to security incidents. This guide covers best practices for implementing comprehensive logging, monitoring, and alerting across your infrastructure to identify suspicious activities, maintain compliance, and support incident response efforts.",
  bestPractices: [
    {
      title: "Implement Centralized Logging",
      description: "Collect and aggregate logs from all systems in a central location for analysis and correlation.",
      command: `# Example rsyslog server configuration (/etc/rsyslog.conf)
# Enable TCP and UDP reception
module(load="imudp")
input(type="imudp" port="514")
module(load="imtcp")
input(type="imtcp" port="514")

# Set file permissions
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022

# Define templates for remote logs
$template RemoteLogs,"/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log"
*.* ?RemoteLogs

# Client configuration (/etc/rsyslog.conf)
*.* @central-syslog-server:514 # UDP
*.* @@central-syslog-server:514 # TCP with reliability`,
    },
    {
      title: "Configure Comprehensive System Logging",
      description: "Enable detailed logging for operating systems, applications, and security events.",
      command: `# Linux: Configure auditd (/etc/audit/auditd.conf)
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
max_log_file = 8
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
write_logs = yes

# Windows: Enable advanced auditing via Group Policy
# Run gpedit.msc > Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration
# PowerShell command to enable all auditing:
auditpol /set /category:* /success:enable /failure:enable`,
    },
    {
      title: "Implement Security Information and Event Management (SIEM)",
      description: "Deploy a SIEM solution to correlate and analyze security events across your infrastructure.",
      command: `# Example Elasticsearch configuration for log storage (elasticsearch.yml)
cluster.name: security-logs
node.name: node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
http.port: 9200
discovery.seed_hosts: ["127.0.0.1"]
cluster.initial_master_nodes: ["node-1"]
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true

# Example Logstash pipeline for log processing (logstash.conf)
input {
  beats {
    port => 5044
  }
  syslog {
    port => 514
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\\[%{POSINT:syslog_pid}\\])?: %{GREEDYDATA:syslog_message}" }
    }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "logstash-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "changeme"
  }
}`,
    },
    {
      title: "Set Up Real-time Alerting",
      description: "Configure alerts for suspicious activities and security incidents.",
      command: `# Example Elasticsearch Watcher alert (via API)
PUT _watcher/watch/failed_login_alert
{
  "trigger": {
    "schedule": {
      "interval": "5m"
    }
  },
  "input": {
    "search": {
      "request": {
        "indices": ["logstash-*"],
        "body": {
          "query": {
            "bool": {
              "must": [
                { "match": { "event.action": "failed-login" } }
              ],
              "filter": {
                "range": {
                  "@timestamp": {
                    "gte": "now-5m"
                  }
                }
              }
            }
          },
          "aggs": {
            "by_source": {
              "terms": {
                "field": "source.ip",
                "min_doc_count": 5
              }
            }
          },
          "size": 0
        }
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.aggregations.by_source.buckets.0.doc_count": {
        "gt": 5
      }
    }
  },
  "actions": {
    "send_email": {
      "email": {
        "to": "security@example.com",
        "subject": "Multiple Failed Logins Detected",
        "body": {
          "html": "Multiple failed logins detected from IP: {{ctx.payload.aggregations.by_source.buckets.0.key}}"
        }
      }
    }
  }
}`,
    },
    {
      title: "Implement File Integrity Monitoring",
      description: "Monitor critical files and directories for unauthorized changes.",
      command: `# Example AIDE configuration (aide.conf)
# Define what directories to monitor
/etc/ PERMS
/bin/ PERMS
/sbin/ PERMS
/usr/bin/ PERMS
/usr/sbin/ PERMS
/boot/ PERMS

# Define what to check
PERMS = p+i+n+u+g+s+m+c+md5

# Initialize the database
# aide --init
# mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Set up a daily cron job to check for changes
# echo "0 3 * * * /usr/sbin/aide --check | mail -s 'AIDE Report' root@localhost" > /etc/cron.d/aide`,
    },
    {
      title: "Implement Network Traffic Monitoring",
      description: "Monitor network traffic for suspicious patterns and potential threats.",
      command: `# Example Zeek (formerly Bro) configuration (zeek.cfg)
# Interface to monitor
interface=eth0

# Log directory
logdir=/var/log/zeek

# Enable protocols to monitor
@load protocols/ftp/software
@load protocols/http/software
@load protocols/ssh/software
@load protocols/ssl/weak-ciphers
@load protocols/smb

# Enable threat detection
@load frameworks/intel/seen
@load frameworks/intel/do_notice
@load policy/frameworks/intel/alerts

# Start Zeek
zeekctl deploy`,
    },
    {
      title: "Establish Log Retention Policies",
      description: "Define how long to keep logs based on compliance requirements and operational needs.",
      command: `# Example logrotate configuration (/etc/logrotate.d/syslog)
/var/log/syslog {
    rotate 14
    daily
    missingok
    notifempty
    delaycompress
    compress
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}

# Example Windows Event Log retention policy (PowerShell)
# Set security log to keep 90 days of events and 4GB max size
wevtutil sl Security /retention:true /maxsize:4294967296

# Set application log to keep 30 days
wevtutil sl Application /retention:true /maxage:30`,
    },
  ],
  tools: [
    {
      name: "Elastic Stack (ELK)",
      description: "Comprehensive log management and analysis platform",
      usage: `# Start Elasticsearch
systemctl start elasticsearch

# Start Kibana
systemctl start kibana

# Configure Logstash pipeline
vim /etc/logstash/conf.d/logstash.conf

# Start Logstash
systemctl start logstash`,
    },
    {
      name: "Graylog",
      description: "Centralized log management platform with search and alerting capabilities",
      usage: `# Access web interface
http://graylog-server:9000

# Configure inputs
# System > Inputs > Select Input > Launch new input

# Create dashboard
# Dashboards > Create dashboard`,
    },
    {
      name: "Wazuh",
      description: "Open source security monitoring solution with log analysis and intrusion detection",
      usage: `# Check agent status
/var/ossec/bin/agent_control -l

# View alerts
/var/ossec/bin/ossec-logtest

# Access web interface
https://wazuh-server:443`,
    },
    {
      name: "Auditd",
      description: "Linux audit framework for monitoring system calls and file access",
      usage: `# Start auditd
systemctl start auditd

# Add rule to monitor file access
auditctl -w /etc/passwd -p rwxa -k passwd_changes

# View audit logs
ausearch -k passwd_changes`,
    },
    {
      name: "Osquery",
      description: "SQL-powered operating system instrumentation, monitoring, and analytics framework",
      usage: `# Run interactive query
osqueryi "SELECT * FROM users WHERE uid = 0;"

# Schedule queries
vim /etc/osquery/osquery.conf

# View logs
cat /var/log/osquery/osqueryd.results.log`,
    },
    {
      name: "Prometheus",
      description: "Monitoring system and time series database with alerting capabilities",
      usage: `# Start Prometheus
prometheus --config.file=/etc/prometheus/prometheus.yml

# Query metrics
curl 'http://localhost:9090/api/v1/query?query=up'

# Access web interface
http://prometheus-server:9090`,
    },
    {
      name: "Grafana",
      description: "Analytics and visualization platform for metrics and logs",
      usage: `# Start Grafana
systemctl start grafana-server

# Access web interface
http://grafana-server:3000

# Add data source
# Configuration > Data Sources > Add data source`,
    },
    {
      name: "OSSEC",
      description: "Host-based intrusion detection system with log analysis and file integrity monitoring",
      usage: `# Check status
/var/ossec/bin/ossec-control status

# View alerts
tail -f /var/ossec/logs/alerts/alerts.log

# Run integrity check
/var/ossec/bin/ossec-syscheckd -t`,
    },
    {
      name: "Sysmon",
      description: "Windows system monitoring tool that logs system activity to the Windows Event Log",
      usage: `# Install Sysmon with config
sysmon.exe -i sysmonconfig.xml

# View logs in Event Viewer
eventvwr.msc > Applications and Services Logs > Microsoft > Windows > Sysmon > Operational

# Export logs to file
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:text > sysmon_logs.txt`,
    },
    {
      name: "Splunk",
      description: "Platform for searching, monitoring, and analyzing machine-generated data",
      usage: `# Start Splunk
/opt/splunk/bin/splunk start

# Add data input
/opt/splunk/bin/splunk add monitor /var/log

# Access web interface
http://splunk-server:8000`,
    },
  ],
  pitfalls: [
    "Collecting too much data without proper analysis capabilities",
    "Not establishing baseline behavior before implementing alerting",
    "Setting up too many alerts leading to alert fatigue",
    "Failing to secure the monitoring infrastructure itself",
    "Not testing alerting mechanisms regularly",
    "Insufficient log retention for compliance or forensic purposes",
    "Overlooking encryption for sensitive log data",
    "Not correlating events across different systems",
    "Inadequate documentation of monitoring procedures",
    "Failing to regularly review and update monitoring rules",
    "Not having incident response procedures tied to monitoring alerts",
    "Overlooking network traffic monitoring in favor of just system logs",
  ],
  references: [
    {
      title: "NIST SP 800-92: Guide to Computer Security Log Management",
      url: "https://csrc.nist.gov/publications/detail/sp/800-92/final",
    },
    {
      title: "SANS Logging and Monitoring Guidelines",
      url: "https://www.sans.org/reading-room/whitepapers/logging/paper/36312",
    },
    {
      title: "CIS Critical Security Controls - Control 8: Audit Log Management",
      url: "https://www.cisecurity.org/controls/audit-log-management",
    },
    {
      title: "MITRE ATT&CK: Defense Evasion - Indicator Removal on Host",
      url: "https://attack.mitre.org/techniques/T1070/",
    },
    {
      title: "OWASP Logging Cheat Sheet",
      url: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
    },
  ],
}

export default function AuditingMonitoringPage() {
  const { title, tagline, icon: Icon, overview, bestPractices, tools, pitfalls, references } = auditingMonitoring

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
                  <CardDescription>Understanding auditing and monitoring fundamentals</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>{overview}</p>

                  <div className="grid gap-4 md:grid-cols-3">
                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <FileText className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Logging</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Collect and store records of system activities, security events, and user actions for analysis
                          and compliance.
                        </p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Search className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Monitoring</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Continuously observe systems, networks, and applications to detect anomalies, performance
                          issues, and security threats.
                        </p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Bell className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Alerting</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Notify security teams of potential incidents, suspicious activities, or policy violations that
                          require investigation.
                        </p>
                      </CardContent>
                    </Card>
                  </div>

                  <Alert>
                    <Shield className="h-4 w-4" />
                    <AlertTitle>Visibility is Key</AlertTitle>
                    <AlertDescription>
                      You can't protect what you can't see. Comprehensive auditing and monitoring provide the visibility
                      needed to detect threats, investigate incidents, and maintain compliance with security
                      requirements.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="best-practices" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle>Best Practices</CardTitle>
                  <CardDescription>Essential configurations for effective auditing and monitoring</CardDescription>
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
                  <CardDescription>Software to help implement auditing and monitoring</CardDescription>
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
                  <CardDescription>Sample configurations for auditing and monitoring</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <h3 className="text-lg font-medium mb-2">Linux Audit Rules Configuration</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# /etc/audit/rules.d/audit.rules

# Delete all existing rules
-D

# Set buffer size to reduce likelihood of lost events
-b 8192

# Monitor for changes to system authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor for changes to system configuration files
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/hosts -p wa -k hosts
-w /etc/network/ -p wa -k network

# Monitor for changes to PAM configuration
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/limits.conf -p wa -k pam
-w /etc/security/pam_env.conf -p wa -k pam
-w /etc/security/namespace.conf -p wa -k pam
-w /etc/security/namespace.init -p wa -k pam

# Monitor for changes to SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd

# Monitor privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor unsuccessful unauthorized access attempts
-a always,exit -F arch=b64 -S open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Monitor use of privileged commands
-a always,exit -F path=/bin/ping -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/traceroute -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor changes to the time
-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -F key=time-change
-a always,exit -F arch=b64 -S clock_settime -F key=time-change
-a always,exit -F arch=b32 -S clock_settime -F key=time-change
-w /etc/localtime -p wa -k time-change

# Make the audit configuration immutable - requires reboot to change
-e 2`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# /etc/audit/rules.d/audit.rules

# Delete all existing rules
-D

# Set buffer size to reduce likelihood of lost events
-b 8192

# Monitor for changes to system authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor for changes to system configuration files
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/hosts -p wa -k hosts
-w /etc/network/ -p wa -k network

# Monitor for changes to PAM configuration
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/limits.conf -p wa -k pam
-w /etc/security/pam_env.conf -p wa -k pam
-w /etc/security/namespace.conf -p wa -k pam
-w /etc/security/namespace.init -p wa -k pam

# Monitor for changes to SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd

# Monitor privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor unsuccessful unauthorized access attempts
-a always,exit -F arch=b64 -S open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Monitor use of privileged commands
-a always,exit -F path=/bin/ping -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/traceroute -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor changes to the time
-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -F key=time-change
-a always,exit -F arch=b64 -S clock_settime -F key=time-change
-a always,exit -F arch=b32 -S clock_settime -F key=time-change
-w /etc/localtime -p wa -k time-change

# Make the audit configuration immutable - requires reboot to change
-e 2\`}
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">Windows Event Forwarding Configuration</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {\`# PowerShell script to configure Windows Event Forwarding

# Step 1: Configure the collector server
# Run on the collector server (central log server)

# Create a new event subscription
wecutil cs "SecurityEvents.xml"

# Content of SecurityEvents.xml:
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>SecurityEvents</SubscriptionId>
  <SubscriptionType>SourceInitiated</SubscriptionType>
  <Description>Collects security events from domain computers</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
  <ConfigurationMode>Normal</ConfigurationMode>
  <Delivery Mode="Push">
    <Batching>
      <MaxItems>5</MaxItems>
      <MaxLatencyTime>900000</MaxLatencyTime>
    </Batching>
    <PushSettings>
      <Heartbeat Interval="900000"/>
    </PushSettings>
  </Delivery>
  <Query>
    <![CDATA[
      <QueryList>
        <Query Id="0">
          <Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=4648 or EventID=4672 or EventID=4720 or EventID=4722 or EventID=4724 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4738 or EventID=4740 or EventID=4767 or EventID=4781 or EventID=4723 or EventID=4725 or EventID=4726)]]</Select>
          <Select Path="System">*[System[(EventID=104 or EventID=7030 or EventID=7040 or EventID=7045)]]</Select>
          <Select Path="Application">*[System[(Level=1 or Level=2 or Level=3)]]</Select>
        </Query>
      </QueryList>
    ]]>
  </Query>
  <ReadExistingEvents>false</ReadExistingEvents>
  <TransportName>HTTP</TransportName>
  <ContentFormat>RenderedText</ContentFormat>
  <Locale Language="en-US"/>
  <LogFile>ForwardedEvents</LogFile>
  <AllowedSourceNonDomainComputers>
  </AllowedSourceNonDomainComputers>
  <AllowedSourceDomainComputers>O:NSG:BAD:P(A;;GA;;;DC)S:</AllowedSourceDomainComputers>
</Subscription>

# Step 2: Configure source computers via Group Policy
# Create a new GPO and configure the following settings:

# Computer Configuration > Policies > Administrative Templates > Windows Components > Event Forwarding
# Configure target Subscription Manager: Enabled
# Value: Server=http://collector.example.com:5985/wsman/SubscriptionManager/WEC

# Computer Configuration > Policies > Administrative Templates > Windows Components > Event Log Service > Security
# Configure logging: Enabled
# Maximum Log Size: 1048576 KB (1 GB)

# Computer Configuration > Windows Settings > Security Settings > Local Policies > Audit Policy
# Configure audit policies as needed

# Step 3: Verify configuration on source computers
# Run on each source computer
gpupdate /force
wecutil qc -quiet
Restart-Service wecsvc\`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() => navigator.clipboard.writeText(\`# PowerShell script to configure Windows Event Forwarding

# Step 1: Configure the collector server
# Run on the collector server (central log server)

# Create a new event subscription
wecutil cs "SecurityEvents.xml"

# Content of SecurityEvents.xml:
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>SecurityEvents</SubscriptionId>
  <SubscriptionType>SourceInitiated</SubscriptionType>
  <Description>Collects security events from domain computers</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
  <ConfigurationMode>Normal</ConfigurationMode>
  <Delivery Mode="Push">
    <Batching>
      <MaxItems>5</MaxItems>
      <MaxLatencyTime>900000</MaxLatencyTime>
    </Batching>
    <PushSettings>
      <Heartbeat Interval="900000"/>
    </PushSettings>
  </Delivery>
  <Query>
    <![CDATA[
      <QueryList>
        <Query Id="0">
          <Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=4648 or EventID=4672 or EventID=4720 or EventID=4722 or EventID=4724 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4738 or EventID=4740 or EventID=4767 or EventID=4781 or EventID=4723 or EventID=4725 or EventID=4726)]]</Select>
          <Select Path="System">*[System[(EventID=104 or EventID=7030 or EventID=7040 or EventID=7045)]]</Select>
          <Select Path="Application">*[System[(Level=1 or Level=2 or Level=3)]]</Select>
        </Query>
      </QueryList>
    ]]>
  </Query>
  <ReadExistingEvents>false</ReadExistingEvents>
  <TransportName>HTTP</TransportName>
  <ContentFormat>RenderedText</ContentFormat>
  <Locale Language="en-US"/>
  <LogFile>ForwardedEvents</LogFile>
  <AllowedSourceNonDomainComputers>
  </AllowedSourceNonDomainComputers>
  <AllowedSourceDomainComputers>O:NSG:BAD:P(A;;GA;;;DC)S:</AllowedSourceDomainComputers>
</Subscription>

# Step 2: Configure source computers via Group Policy
# Create a new GPO and configure the following settings:

# Computer Configuration > Policies > Administrative Templates > Windows Components > Event Forwarding
# Configure target Subscription Manager: Enabled
# Value: Server=http://collector.example.com:5985/wsman/SubscriptionManager/WEC

# Computer Configuration > Policies > Administrative Templates > Windows Components > Event Log Service > Security
# Configure logging: Enabled
# Maximum Log Size: 1048576 KB (1 GB)

# Computer Configuration > Windows Settings > Security Settings > Local Policies > Audit Policy
# Configure audit policies as needed

# Step 3: Verify configuration on source computers
# Run on each source computer
gpupdate /force
wecutil qc -quiet
Restart-Service wecsvc`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">Elasticsearch SIEM Alert Configuration</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# Elasticsearch SIEM Alert Rule (JSON)

{
  "rule_id": "brute-force-detection",
  "risk_score": 75,
  "description": "Detects potential brute force attacks based on failed authentication attempts",
  "interval": "5m",
  "name": "Potential Brute Force Attack",
  "severity": "high",
  "tags": ["authentication", "brute-force", "attack"],
  "type": "threshold",
  "from": "now-5m",
  "query": "event.category:authentication and event.outcome:failure",
  "language": "kuery",
  "size": 100,
  "threshold": {
    "field": "source.ip",
    "value": 5
  },
  "threat": {
    "framework": "MITRE ATT&CK",
    "tactic": {
      "id": "TA0006",
      "name": "Credential Access",
      "reference": "https://attack.mitre.org/tactics/TA0006/"
    },
    "technique": [
      {
        "id": "T1110",
        "name": "Brute Force",
        "reference": "https://attack.mitre.org/techniques/T1110/"
      }
    ]
  },
  "actions": [
    {
      "action_type_id": ".email",
      "params": {
        "to": ["security@example.com"],
        "subject": "ALERT: Potential Brute Force Attack Detected",
        "body": {
          "message": "Potential brute force attack detected from {{context.source.ip}} with {{context.threshold.count}} failed login attempts in the last 5 minutes."
        }
      }
    },
    {
      "action_type_id": ".slack",
      "params": {
        "message": "ALERT: Potential brute force attack detected from {{context.source.ip}} with {{context.threshold.count}} failed login attempts in the last 5 minutes."
      }
    }
  ],
  "enabled": true,
  "throttle": "1h"
}`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# Elasticsearch SIEM Alert Rule (JSON)

{
  "rule_id": "brute-force-detection",
  "risk_score": 75,
  "description": "Detects potential brute force attacks based on failed authentication attempts",
  "interval": "5m",
  "name": "Potential Brute Force Attack",
  "severity": "high",
  "tags": ["authentication", "brute-force", "attack"],
  "type": "threshold",
  "from": "now-5m",
  "query": "event.category:authentication and event.outcome:failure",
  "language": "kuery",
  "size": 100,
  "threshold": {
    "field": "source.ip",
    "value": 5
  },
  "threat": {
    "framework": "MITRE ATT&CK",
    "tactic": {
      "id": "TA0006",
      "name": "Credential Access",
      "reference": "https://attack.mitre.org/tactics/TA0006/"
    },
    "technique": [
      {
        "id": "T1110",
        "name": "Brute Force",
        "reference": "https://attack.mitre.org/techniques/T1110/"
      }
    ]
  },
  "actions": [
    {
      "action_type_id": ".email",
      "params": {
        "to": ["security@example.com"],
        "subject": "ALERT: Potential Brute Force Attack Detected",
        "body": {
          "message": "Potential brute force attack detected from {{context.source.ip}} with {{context.threshold.count}} failed login attempts in the last 5 minutes."
        }
      }
    },
    {
      "action_type_id": ".slack",
      "params": {
        "message": "ALERT: Potential brute force attack detected from {{context.source.ip}} with {{context.threshold.count}} failed login attempts in the last 5 minutes."
      }
    }
  ],
  "enabled": true,
  "throttle": "1h"
}`)
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
                  <CardDescription>Mistakes to avoid when implementing auditing and monitoring</CardDescription>
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
                  <Link href="/category/linux-os" className="block text-sm hover:underline">
                    Linux OS
                  </Link>
                  <Link href="/category/windows-os" className="block text-sm hover:underline">
                    Windows OS
                  </Link>
                  <Link href="/category/cloud-security" className="block text-sm hover:underline">
                    Cloud Security
                  </Link>
                </nav>
              </CardContent>
            </Card>

            <Alert className="mt-6">
              <Clock className="h-4 w-4" />
              <AlertTitle>Log Retention</AlertTitle>
              <AlertDescription className="text-sm">
                Ensure your log retention policies meet both operational needs and compliance requirements. Different
                types of logs may need different retention periods.
              </AlertDescription>
            </Alert>

            <Alert className="mt-6">
              <Database className="h-4 w-4" />
              <AlertTitle>Storage Planning</AlertTitle>
              <AlertDescription className="text-sm">
                Plan for adequate storage capacity. Security logs can grow rapidly, especially in large environments
                with comprehensive auditing enabled.
              </AlertDescription>
            </Alert>
          </div>
        </div>
      </div>
    </div>
  )
}

