"use client"

import Link from "next/link"
import {
  ChevronRight,
  Copy,
  ExternalLink,
  Shield,
  AlertTriangle,
  BookOpen,
  Cloud,
  Key,
  Database,
  ServerCrash,
  Network,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

// Cloud security category data
const cloudSecurity = {
  title: "Cloud Security Hardening",
  tagline: "Protect your cloud infrastructure and services across major providers",
  icon: Cloud,
  overview:
    "Cloud security is the protection of data, applications, and infrastructure in cloud computing environments. It requires a shared responsibility model between the cloud provider and the customer. This guide covers essential configurations, best practices, and tools to secure your cloud environment across AWS, Azure, and Google Cloud Platform.",
  bestPractices: [
    {
      title: "Implement Identity and Access Management (IAM)",
      description: "Follow the principle of least privilege and regularly review permissions.",
      command: `# AWS - List IAM users with administrative access
aws iam list-users | jq '.Users[].UserName' | xargs -I {} aws iam list-attached-user-policies --user-name {} | grep 'AdministratorAccess'

# Azure - List role assignments
az role assignment list --all

# GCP - List IAM policies
gcloud projects get-iam-policy PROJECT_ID`,
    },
    {
      title: "Enable Multi-Factor Authentication (MFA)",
      description: "Require MFA for all users, especially those with elevated privileges.",
      command: `# AWS - List users without MFA
aws iam list-users --query 'Users[?!MFADevices].[UserName]' --output text

# Azure - Enable MFA for users
az ad user list --query "[].userPrincipalName" | xargs -I {} az ad user authentication get-method --user-principal-name {}

# GCP - View 2-Step Verification Status (Use Google Admin Console)`,
    },
    {
      title: "Encrypt data at rest and in transit",
      description: "Use encryption for all sensitive data stored in the cloud and in transit.",
      command: `# AWS - Check S3 bucket encryption
aws s3api get-bucket-encryption --bucket BUCKET_NAME

# Azure - Check storage account encryption
az storage account show --name ACCOUNT_NAME --resource-group RESOURCE_GROUP --query encryption

# GCP - Check GCS bucket encryption
gsutil kms encryption gs://BUCKET_NAME`,
    },
    {
      title: "Configure Network Security",
      description: "Use security groups, firewall rules, and private networks to protect resources.",
      command: `# AWS - Review security group rules
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupName,GroupId,Description,IpPermissions[*]]'

# Azure - Review network security groups
az network nsg list -o table

# GCP - Review firewall rules
gcloud compute firewall-rules list`,
    },
    {
      title: "Enable Cloud Logging and Monitoring",
      description: "Set up comprehensive logging, monitoring, and alerting for security events.",
      command: `# AWS - Enable CloudTrail
aws cloudtrail create-trail --name TRAIL_NAME --s3-bucket-name BUCKET_NAME --is-multi-region-trail
aws cloudtrail start-logging --name TRAIL_NAME

# Azure - View activity logs
az monitor activity-log list --offset 72h

# GCP - View Cloud Audit Logs
gcloud logging read "logName=projects/PROJECT_ID/logs/cloudaudit.googleapis.com"`,
    },
  ],
  tools: [
    {
      name: "AWS CloudWatch",
      description: "Monitoring and observability service for AWS resources and applications",
      usage: `# View recent log events
aws logs get-log-events --log-group-name LOG_GROUP --log-stream-name LOG_STREAM

# Create a CloudWatch alarm
aws cloudwatch put-metric-alarm --alarm-name cpu-alarm --metric-name CPUUtilization --namespace AWS/EC2 --statistic Average --period 300 --threshold 70 --comparison-operator GreaterThanThreshold --dimensions Name=InstanceId,Value=INSTANCE_ID --evaluation-periods 2 --alarm-actions ARN`,
    },
    {
      name: "Azure Security Center",
      description: "Unified security management and advanced threat protection for hybrid cloud workloads",
      usage: `# View security recommendations
az security assessment list

# View security alerts
az security alert list`,
    },
    {
      name: "Google Cloud Security Command Center",
      description: "Security and risk management platform for Google Cloud resources",
      usage: `# List findings
gcloud scc findings list --organization=ORGANIZATION_ID --filter="state=\"ACTIVE\""

# Update security marks
gcloud scc findings update --organization=ORGANIZATION_ID --finding=FINDING_ID --security-marks=KEY=VALUE`,
    },
    {
      name: "CloudSploit",
      description: "Open-source security configuration monitoring for multiple cloud providers",
      usage: `# Install CloudSploit
npm install -g cloudsploit

# Run a scan
cloudsploit scan --console --config /path/to/credentials`,
    },
    {
      name: "Prowler",
      description: "AWS security best practices assessment, auditing, hardening and forensics tool",
      usage: `# Install Prowler
pip install prowler

# Run a full assessment
prowler -M csv,json -F /tmp/prowler-output`,
    },
    {
      name: "Checkov",
      description: "Static code analysis tool for infrastructure-as-code",
      usage: `# Install Checkov
pip install checkov

# Scan Terraform files
checkov -d /path/to/terraform/files

# Scan CloudFormation template
checkov -f template.yaml`,
    },
  ],
  pitfalls: [
    "Misconfigured public S3 buckets or storage containers exposing sensitive data",
    "Not following the principle of least privilege in IAM roles and policies",
    "Leaving default credentials or using weak passwords for cloud services",
    "Neglecting to encrypt sensitive data at rest and in transit",
    "Not implementing adequate logging and monitoring for security events",
    "Ignoring the shared responsibility model and assuming the cloud provider handles all security",
    "Failing to secure API keys, access tokens, and other secrets",
    "Not implementing proper network segmentation and security controls",
  ],
  references: [
    {
      title: "AWS Well-Architected Framework - Security Pillar",
      url: "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html",
    },
    {
      title: "Microsoft Azure Security Best Practices",
      url: "https://docs.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns",
    },
    {
      title: "Google Cloud Security Best Practices",
      url: "https://cloud.google.com/security/best-practices",
    },
    {
      title: "CIS Benchmarks for Cloud Providers",
      url: "https://www.cisecurity.org/benchmark/cloud_providers",
    },
    {
      title: "NIST SP 800-204: Security Strategies for Microservices-based Applications",
      url: "https://csrc.nist.gov/publications/detail/sp/800-204/final",
    },
  ],
}

export default function CloudSecurityPage() {
  const { title, tagline, icon: Icon, overview, bestPractices, tools, pitfalls, references } = cloudSecurity

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
                  <CardDescription>Understanding cloud security fundamentals</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>{overview}</p>

                  <div className="grid gap-4 md:grid-cols-3">
                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Key className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Identity & Access</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Proper IAM configuration is critical to secure cloud environments. Implement least privilege
                          principle and strong authentication.
                        </p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Database className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Data Protection</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Encrypt sensitive data at rest and in transit. Implement proper access controls and backup
                          solutions.
                        </p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Network className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Network Security</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Use security groups, firewall rules, and VPCs to isolate and protect resources from
                          unauthorized access.
                        </p>
                      </CardContent>
                    </Card>
                  </div>

                  <Alert>
                    <Shield className="h-4 w-4" />
                    <AlertTitle>Shared Responsibility Model</AlertTitle>
                    <AlertDescription>
                      Cloud security is a shared responsibility. Providers secure the infrastructure, but customers are
                      responsible for securing their data, applications, and access management.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="best-practices" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle>Best Practices</CardTitle>
                  <CardDescription>Essential security configurations for cloud environments</CardDescription>
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
                  <CardDescription>Software to help secure and audit cloud environments</CardDescription>
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
                  <CardDescription>Sample configurations for common cloud security controls</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <h3 className="text-lg font-medium mb-2">AWS S3 Bucket Policy for Enforcing Encryption</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyIncorrectEncryptionHeader",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::BUCKET_NAME/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        }
      }
    },
    {
      "Sid": "DenyUnEncryptedObjectUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::BUCKET_NAME/*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": "true"
        }
      }
    }
  ]
}`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyIncorrectEncryptionHeader",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::BUCKET_NAME/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        }
      }
    },
    {
      "Sid": "DenyUnEncryptedObjectUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::BUCKET_NAME/*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": "true"
        }
      }
    }
  ]
}`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">Azure Network Security Group Rules</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# Create a Network Security Group
az network nsg create \\
  --resource-group RESOURCE_GROUP \\
  --name SECURITY_GROUP_NAME

# Allow SSH from admin IP only
az network nsg rule create \\
  --resource-group RESOURCE_GROUP \\
  --nsg-name SECURITY_GROUP_NAME \\
  --name AllowSSH \\
  --protocol tcp \\
  --priority 100 \\
  --destination-port-range 22 \\
  --source-address-prefixes ADMIN_IP_ADDRESS \\
  --access allow

# Allow HTTPS inbound
az network nsg rule create \\
  --resource-group RESOURCE_GROUP \\
  --nsg-name SECURITY_GROUP_NAME \\
  --name AllowHTTPS \\
  --protocol tcp \\
  --priority 110 \\
  --destination-port-range 443 \\
  --source-address-prefixes '*' \\
  --access allow

# Deny all other inbound traffic
az network nsg rule create \\
  --resource-group RESOURCE_GROUP \\
  --nsg-name SECURITY_GROUP_NAME \\
  --name DenyAllInbound \\
  --priority 4096 \\
  --source-address-prefixes '*' \\
  --destination-port-ranges '*' \\
  --access deny`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# Create a Network Security Group
az network nsg create \\
  --resource-group RESOURCE_GROUP \\
  --name SECURITY_GROUP_NAME

# Allow SSH from admin IP only
az network nsg rule create \\
  --resource-group RESOURCE_GROUP \\
  --nsg-name SECURITY_GROUP_NAME \\
  --name AllowSSH \\
  --protocol tcp \\
  --priority 100 \\
  --destination-port-range 22 \\
  --source-address-prefixes ADMIN_IP_ADDRESS \\
  --access allow

# Allow HTTPS inbound
az network nsg rule create \\
  --resource-group RESOURCE_GROUP \\
  --nsg-name SECURITY_GROUP_NAME \\
  --name AllowHTTPS \\
  --protocol tcp \\
  --priority 110 \\
  --destination-port-range 443 \\
  --source-address-prefixes '*' \\
  --access allow

# Deny all other inbound traffic
az network nsg rule create \\
  --resource-group RESOURCE_GROUP \\
  --nsg-name SECURITY_GROUP_NAME \\
  --name DenyAllInbound \\
  --priority 4096 \\
  --source-address-prefixes '*' \\
  --destination-port-ranges '*' \\
  --access deny`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">Google Cloud IAM Policy with Least Privilege</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# Create a custom role with minimal permissions
gcloud iam roles create customRole \\
  --project=PROJECT_ID \\
  --title="Custom Role" \\
  --description="A custom role with minimal permissions" \\
  --permissions=compute.instances.get,compute.instances.list

# Assign role to specific user
gcloud projects add-iam-policy-binding PROJECT_ID \\
  --member="user:USER_EMAIL" \\
  --role="projects/PROJECT_ID/roles/customRole"

# Grant time-limited access
gcloud iam service-accounts add-iam-policy-binding \\
  --role="roles/iam.serviceAccountUser" \\
  --member="user:USER_EMAIL" \\
  --condition="title=temporary_access,description=Grant temporary access,expression=request.time < timestamp('2023-12-31T23:59:59Z')" \\
  SERVICE_ACCOUNT_EMAIL`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# Create a custom role with minimal permissions
gcloud iam roles create customRole \\
  --project=PROJECT_ID \\
  --title="Custom Role" \\
  --description="A custom role with minimal permissions" \\
  --permissions=compute.instances.get,compute.instances.list

# Assign role to specific user
gcloud projects add-iam-policy-binding PROJECT_ID \\
  --member="user:USER_EMAIL" \\
  --role="projects/PROJECT_ID/roles/customRole"

# Grant time-limited access
gcloud iam service-accounts add-iam-policy-binding \\
  --role="roles/iam.serviceAccountUser" \\
  --member="user:USER_EMAIL" \\
  --condition="title=temporary_access,description=Grant temporary access,expression=request.time < timestamp('2023-12-31T23:59:59Z')" \\
  SERVICE_ACCOUNT_EMAIL`)
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
                  <CardDescription>Mistakes to avoid when securing cloud environments</CardDescription>
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
                  <Link href="/category/virtualization-containers" className="block text-sm hover:underline">
                    Virtualization & Containers
                  </Link>
                  <Link href="/category/auditing-monitoring" className="block text-sm hover:underline">
                    Auditing & Monitoring
                  </Link>
                </nav>
              </CardContent>
            </Card>

            <Alert className="mt-6">
              <ServerCrash className="h-4 w-4" />
              <AlertTitle>Cloud Provider Specific</AlertTitle>
              <AlertDescription className="text-sm">
                Remember that each cloud provider has unique security features. Always consult provider-specific
                documentation for detailed guidance.
              </AlertDescription>
            </Alert>
          </div>
        </div>
      </div>
    </div>
  )
}

