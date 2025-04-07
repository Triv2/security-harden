"use client"

import Link from "next/link"
import {
  ChevronRight,
  Copy,
  ExternalLink,
  Shield,
  AlertTriangle,
  BookOpen,
  Server,
  Box,
  Layers,
  FileCode,
  Cpu,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

// Virtualization & Containers category data
const virtualizationContainers = {
  title: "Virtualization & Container Security",
  tagline: "Secure virtual machines, containers, and orchestration platforms",
  icon: Server,
  overview:
    "Virtualization and containerization technologies provide significant benefits for resource utilization, scalability, and deployment flexibility, but they also introduce unique security challenges. This guide covers essential security configurations, best practices, and tools to secure virtualized environments and containerized applications across various platforms.",
  bestPractices: [
    {
      title: "Secure Hypervisor Configuration",
      description: "Harden the hypervisor to prevent VM escape and other virtualization-specific attacks.",
      command: `# Example ESXi lockdown mode configuration
# Enable lockdown mode via ESXi Shell
vim-cmd hostsvc/lockdown_mode_enter

# Check lockdown mode status
vim-cmd hostsvc/lockdown_mode_level

# Configure ESXi firewall
esxcli network firewall set --enabled true
esxcli network firewall set --default-action false

# Allow only necessary services
esxcli network firewall ruleset set --ruleset-id sshClient --enabled false
esxcli network firewall ruleset set --ruleset-id sshServer --enabled true
esxcli network firewall ruleset set --ruleset-id nfsClient --enabled false

# Disable unnecessary services
/etc/init.d/TSM-SSH stop
chkconfig TSM-SSH off

# Disable Shell and SSH warnings
esxcli system settings advanced set -o /UserVars/SuppressShellWarning -i 1
esxcli system settings advanced set -o /UserVars/ESXiShellTimeOut -i 600`,
    },
    {
      title: "Implement VM Isolation",
      description: "Ensure proper isolation between virtual machines to prevent unauthorized access and data leakage.",
      command: `# Example KVM/QEMU security settings
# In /etc/libvirt/qemu.conf:

# Run QEMU processes as a non-root user
user = "qemu"
group = "qemu"

# Disable file system access between VMs
security_driver = "selinux"
security_default_confined = 1
security_require_confined = 1

# Disable shared memory
namespaces = [ "mount" ]

# Disable memory ballooning
set_process_name = 1
seccomp_sandbox = 1

# Restart libvirtd to apply changes
systemctl restart libvirtd`,
    },
    {
      title: "Secure Container Images",
      description: "Use minimal, trusted base images and scan for vulnerabilities before deployment.",
      command: `# Use official minimal images
FROM alpine:3.15

# Scan images for vulnerabilities
docker scan myapp:latest

# Use multi-stage builds to reduce attack surface
FROM node:16-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:16-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY package*.json ./
USER node
CMD ["node", "dist/index.js"]

# Sign and verify container images
docker trust sign myapp:latest
docker trust inspect --pretty myapp:latest`,
    },
    {
      title: "Implement Container Runtime Security",
      description: "Configure container runtime with security best practices to limit container capabilities.",
      command: `# Run containers with limited capabilities
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx

# Use read-only root filesystem
docker run --read-only nginx

# Set memory and CPU limits
docker run --memory="256m" --cpu-shares=1024 nginx

# Use security options
docker run --security-opt=no-new-privileges --security-opt=apparmor=docker-default nginx

# Use user namespaces
docker run --userns-remap=default nginx

# Use seccomp profiles
docker run --security-opt seccomp=/path/to/seccomp.json nginx

# Example seccomp profile (seccomp.json)
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "accept", "access", "arch_prctl", "bind", "brk", "capget",
        "capset", "chdir", "chmod", "chown", "close", "connect",
        "dup", "dup2", "epoll_create", "epoll_ctl", "epoll_wait",
        "execve", "exit", "exit_group", "fcntl", "fstat", "futex",
        "getcwd", "getdents", "getgid", "getpid", "getppid", "getrandom",
        "getrlimit", "getsockname", "getsockopt", "gettid", "gettimeofday",
        "getuid", "ioctl", "listen", "lseek", "mkdir", "mmap", "mprotect",
        "munmap", "nanosleep", "open", "pipe", "poll", "prctl",
        "pread64", "prlimit64", "read", "recvfrom", "recvmsg", "rename",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sendfile",
        "sendmsg", "sendto", "setgid", "setgroups", "setitimer",
        "setpgid", "setsockopt", "setuid", "socket", "socketpair",
        "stat", "statfs", "sysinfo", "umask", "uname", "unlink",
        "wait4", "write", "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}`,
    },
    {
      title: "Secure Kubernetes Deployments",
      description: "Implement security best practices for Kubernetes clusters and workloads.",
      command: `# Use Pod Security Policies or Pod Security Standards
# Example Pod Security Context in deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: secure-app
        image: myapp:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        resources:
          limits:
            cpu: "1"
            memory: "512Mi"
          requests:
            cpu: "0.5"
            memory: "256Mi"

# Use Network Policies to restrict pod communication
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress

# Allow specific traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080`,
    },
    {
      title: "Implement Container Image Scanning",
      description: "Regularly scan container images for vulnerabilities and malware.",
      command: `# Using Trivy to scan container images
# Install Trivy
apt-get install trivy

# Scan a container image
trivy image myapp:latest

# Scan with JSON output
trivy image -f json -o results.json myapp:latest

# Scan with severity filtering
trivy image --severity HIGH,CRITICAL myapp:latest

# Scan and fail on specific severity
trivy image --exit-code 1 --severity CRITICAL myapp:latest

# Integrate with CI/CD pipeline (example GitHub Actions workflow)
name: Container Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Build image\
      run: docker build -t myapp:{{ github.sha }} .
    - name: Scan image
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: myapp:{{ github.sha }}
        format: 'table'
        exit-code: '1'
        severity: 'CRITICAL,HIGH'ge-ref: myapp:{{ github.sha }}
        format: 'table'
        exit-code: '1'
        severity: 'CRITICAL,HIGH'`,
    },
    {
      title: "Secure Container Orchestration",
      description: "Implement security controls for container orchestration platforms like Kubernetes.",
      command: `# Secure Kubernetes API Server
# In kube-apiserver.yaml:
spec:
  containers:
  - command:
    - kube-apiserver
    - --anonymous-auth=false
    - --audit-log-path=/var/log/kubernetes/audit.log
    - --audit-log-maxage=30
    - --audit-log-maxbackup=10
    - --audit-log-maxsize=100
    - --authorization-mode=Node,RBAC
    - --enable-admission-plugins=NodeRestriction,PodSecurityPolicy,ServiceAccount
    - --encryption-provider-config=/etc/kubernetes/encryption/encryption.yaml
    - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
    - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key
    - --client-ca-file=/etc/kubernetes/pki/ca.crt

# Use RBAC for access control
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "watch", "list"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: User
  name: jane
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io`,
    },
  ],
  tools: [
    {
      name: "Docker Bench for Security",
      description: "Script that checks for dozens of common best-practices around deploying Docker containers in production",
      usage: `# Run the script
./docker-bench-security.sh

# Run specific checks
./docker-bench-security.sh -c container_images

# Output to file
./docker-bench-security.sh -l /tmp/docker-bench-results.log`,
    },
    {
      name: "Trivy",
      description: "Comprehensive vulnerability scanner for containers and other artifacts",
      usage: `# Scan a container image
trivy image alpine:3.15

# Scan filesystem
trivy fs /path/to/project

# Scan Kubernetes cluster
trivy k8s --report summary cluster

# Scan with config file
trivy config --severity HIGH,CRITICAL kubernetes/*.yaml`,
    },
    {
      name: "Clair",
      description: "Open source project for static analysis of vulnerabilities in container images",
      usage: `# Run Clair server
docker run -p 6060:6060 quay.io/projectquay/clair:latest

# Scan with clairctl
clairctl analyze --addr http://localhost:6060 alpine:latest`,
    },
    {
      name: "Falco",
      description: "Cloud-native runtime security tool designed to detect anomalous activity in containers",
      usage: `# Install Falco
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
apt-get update -y
apt-get install -y falco

# Run Falco
systemctl start falco

# Check Falco logs
journalctl -fu falco`,
    },
    {
      name: "kube-bench",
      description: "Tool that checks whether Kubernetes is deployed according to security best practices",
      usage: `# Run kube-bench
kube-bench

# Run specific checks
kube-bench --check 1.2.1

# Run checks for specific Kubernetes component
kube-bench run --targets master`,
    },
    {
      name: "kube-hunter",
      description: "Tool that hunts for security weaknesses in Kubernetes clusters",
      usage: `# Run kube-hunter
kube-hunter

# Run in active hunting mode
kube-hunter --active

# Scan remote cluster
kube-hunter --remote 10.0.0.1`,
    },
    {
      name: "Anchore Engine",
      description: "Open-source tool for deep container image analysis and policy-based compliance",
      usage: `# Run Anchore Engine
docker-compose up -d

# Add an image for scanning
anchore-cli image add docker.io/library/alpine:latest

# Get scan results
anchore-cli image vuln docker.io/library/alpine:latest os`,
    },
    {
      name: "Sysdig Secure",
      description: "Container security platform that includes vulnerability management, compliance, and runtime security",
      usage: `# Install Sysdig agent
curl -s https://download.sysdig.com/stable/install-agent | sudo bash -s -- --access-key YOUR_ACCESS_KEY

# Run Sysdig Secure
sysdig-agent start

# Check agent status
sysdig-agent status`,
    },
  ],
  pitfalls: [
    "Using outdated or unpatched hypervisors and container runtimes",
    "Running containers with excessive privileges or as root",
    "Not scanning container images for vulnerabilities before deployment",
    "Using untrusted or outdated base images for containers",
    "Failing to implement proper network segmentation between VMs or containers",
    "Not encrypting sensitive data in virtualized environments",
    "Neglecting to implement resource limits for containers and VMs",
    "Sharing sensitive information via environment variables in containers",
    "Not implementing proper access controls for container registries and orchestration platforms",
    "Failing to monitor container and VM activities for suspicious behavior",
    "Using default or weak credentials for management interfaces",
    "Not implementing proper backup and disaster recovery for virtualized environments",
  ],
  references: [
    {
      title: "CIS Benchmarks for Docker",
      url: "https://www.cisecurity.org/benchmark/docker/",
    },
    {
      title: "CIS Benchmarks for Kubernetes",
      url: "https://www.cisecurity.org/benchmark/kubernetes/",
    },
    {
      title: "NIST SP 800-190: Application Container Security Guide",
      url: "https://csrc.nist.gov/publications/detail/sp/800-190/final",
    },
    {
      title: "Kubernetes Security Best Practices",
      url: "https://kubernetes.io/docs/concepts/security/",
    },
    {
      title: "Docker Security Documentation",
      url: "https://docs.docker.com/engine/security/",
    },
    {
      title: "VMware Security Hardening Guides",
      url: "https://www.vmware.com/security/hardening-guides.html",
    },
    {
      title: "OWASP Docker Security Cheat Sheet",
      url: "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
    },
  ],
}

export default function VirtualizationContainersPage() {
  const { title, tagline, icon: Icon, overview, bestPractices, tools, pitfalls, references } = virtualizationContainers

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
                  <CardDescription>Understanding virtualization and container security fundamentals</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>{overview}</p>

                  <div className="grid gap-4 md:grid-cols-3">
                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Cpu className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Virtualization Security</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Secure hypervisors, virtual machines, and management interfaces to prevent VM escape and
                          unauthorized access to virtualized resources.
                        </p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Box className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Container Security</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Implement security controls for container images, runtimes, and build processes to ensure
                          secure containerized applications.
                        </p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Layers className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Orchestration Security</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Secure container orchestration platforms like Kubernetes with proper authentication,
                          authorization, and network policies.
                        </p>
                      </CardContent>
                    </Card>
                  </div>

                  <Alert>
                    <Shield className="h-4 w-4" />
                    <AlertTitle>Shared Responsibility</AlertTitle>
                    <AlertDescription>
                      Security in virtualized and containerized environments is a shared responsibility. The platform
                      provides some security controls, but you must also implement proper security measures within your
                      VMs and containers.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="best-practices" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle>Best Practices</CardTitle>
                  <CardDescription>Essential security configurations for virtualization and containers</CardDescription>
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
                  <CardDescription>Software to help secure virtualized and containerized environments</CardDescription>
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
                  <CardDescription>Sample configurations for securing virtualization and containers</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <h3 className="text-lg font-medium mb-2">Secure Docker Daemon Configuration</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# /etc/docker/daemon.json
{
  "icc": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "userns-remap": "default",
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "seccomp-profile": "/etc/docker/seccomp-profile.json",
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  },
  "selinux-enabled": true,
  "tls": true,
  "tlscacert": "/etc/docker/ca.pem",
  "tlscert": "/etc/docker/server-cert.pem",
  "tlskey": "/etc/docker/server-key.pem",
  "tlsverify": true
}

# Restart Docker to apply changes
systemctl restart docker`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# /etc/docker/daemon.json
{
  "icc": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "userns-remap": "default",
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "seccomp-profile": "/etc/docker/seccomp-profile.json",
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  },
  "selinux-enabled": true,
  "tls": true,
  "tlscacert": "/etc/docker/ca.pem",
  "tlscert": "/etc/docker/server-cert.pem",
  "tlskey": "/etc/docker/server-key.pem",
  "tlsverify": true
}

# Restart Docker to apply changes
systemctl restart docker`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">Secure Dockerfile Example</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# Use specific version of minimal base image
FROM alpine:3.15

# Set maintainer label
LABEL maintainer="security@example.com"

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Install dependencies with version pinning
RUN apk add --no-cache nodejs=16.14.2-r0 npm=8.1.3-r0

# Update packages and clean up
RUN apk update && apk upgrade && rm -rf /var/cache/apk/*

# Copy application files with proper ownership
COPY --chown=appuser:appgroup . .

# Install dependencies
RUN npm ci --production && npm cache clean --force

# Set proper file permissions
RUN chmod -R 550 /app && \
    find /app -type f -exec chmod 440 {} \; && \
    find /app -type d -exec chmod 550 {} \;

# Scan for vulnerabilities
RUN npm audit --production

# Switch to non-root user
USER appuser

# Expose only necessary ports
EXPOSE 3000

# Use specific command with arguments
CMD ["node", "server.js"]

# Set health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# Use specific version of minimal base image
FROM alpine:3.15

# Set maintainer label
LABEL maintainer="security@example.com"

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Install dependencies with version pinning
RUN apk add --no-cache nodejs=16.14.2-r0 npm=8.1.3-r0

# Update packages and clean up
RUN apk update && apk upgrade && rm -rf /var/cache/apk/*

# Copy application files with proper ownership
COPY --chown=appuser:appgroup . .

# Install dependencies
RUN npm ci --production && npm cache clean --force

# Set proper file permissions
RUN chmod -R 550 /app && \\
    find /app -type f -exec chmod 440 {} \\; && \\
    find /app -type d -exec chmod 550 {} \\;

# Scan for vulnerabilities
RUN npm audit --production

# Switch to non-root user
USER appuser

# Expose only necessary ports
EXPOSE 3000

# Use specific command with arguments
CMD ["node", "server.js"]

# Set health check
HEALTHCHECK --interval=30s --timeout=3s \\
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">Kubernetes Security Context</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# secure-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  # Pod-level security context
  securityContext:
    runAsNonRoot: true
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: secure-container
    image: nginx:1.21
    # Container-level security context
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsUser: 1000
      runAsGroup: 3000
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
    resources:
      limits:
        cpu: "1"
        memory: "512Mi"
      requests:
        cpu: "0.5"
        memory: "256Mi"
    ports:
    - containerPort: 8080
      name: http
    volumeMounts:
    - name: tmp-volume
      mountPath: /tmp
    - name: nginx-config
      mountPath: /etc/nginx/conf.d
      readOnly: true
  volumes:
  - name: tmp-volume
    emptyDir: {}
  - name: nginx-config
    configMap:
      name: nginx-config`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# secure-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  # Pod-level security context
  securityContext:
    runAsNonRoot: true
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: secure-container
    image: nginx:1.21
    # Container-level security context
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsUser: 1000
      runAsGroup: 3000
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
    resources:
      limits:
        cpu: "1"
        memory: "512Mi"
      requests:
        cpu: "0.5"
        memory: "256Mi"
    ports:
    - containerPort: 8080
      name: http
    volumeMounts:
    - name: tmp-volume
      mountPath: /tmp
    - name: nginx-config
      mountPath: /etc/nginx/conf.d
      readOnly: true
  volumes:
  - name: tmp-volume
    emptyDir: {}
  - name: nginx-config
    configMap:
      name: nginx-config`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">Kubernetes Network Policy</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-allow
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-allow
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53`)
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
                  <CardDescription>
                    Mistakes to avoid when securing virtualized and containerized environments
                  </CardDescription>
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
                  <Link href="/category/linux-os" className="block text-sm hover:underline">
                    Linux OS
                  </Link>
                  <Link href="/category/cloud-security" className="block text-sm hover:underline">
                    Cloud Security
                  </Link>
                  <Link href="/category/network-security" className="block text-sm hover:underline">
                    Network Security
                  </Link>
                </nav>
              </CardContent>
            </Card>

            <Alert className="mt-6">
              <FileCode className="h-4 w-4" />
              <AlertTitle>Infrastructure as Code</AlertTitle>
              <AlertDescription className="text-sm">
                Consider using Infrastructure as Code (IaC) tools like Terraform or Ansible to define and deploy secure
                virtualization and container configurations consistently and reproducibly.
              </AlertDescription>
            </Alert>
          </div>
        </div>
      </div>
    </div>
  )
}

