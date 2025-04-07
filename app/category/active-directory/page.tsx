"use client"

import Link from "next/link"
import {
  ChevronRight,
  Copy,
  ExternalLink,
  Shield,
  AlertTriangle,
  BookOpen,
  Users,
  FileText,
  Key,
  Database,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

// Active Directory category data
const activeDirectory = {
  title: "Active Directory Security Hardening",
  tagline: "Protect your directory services and identity management infrastructure",
  icon: Users,
  overview:
    "Active Directory (AD) is a critical component of most enterprise environments, serving as the central authentication and authorization service. Due to its importance, it's a prime target for attackers. This guide covers essential configurations, best practices, and tools to secure your Active Directory infrastructure against common threats and vulnerabilities.",
  bestPractices: [
    {
      title: "Implement Tiered Administration Model",
      description:
        "Separate administrative accounts into tiers to limit the impact of credential theft and lateral movement.",
      command: `# PowerShell script to identify administrative accounts not following tiered model
$adminGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
$adminAccounts = foreach ($group in $adminGroups) {
    Get-ADGroupMember -Identity $group | Get-ADUser -Properties SamAccountName, Enabled, LastLogonDate, PasswordLastSet
}

# Check for admin accounts used for regular activities
$adminAccounts | Where-Object { $_.Enabled -eq $true } | 
    Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet |
    Format-Table -AutoSize`,
    },
    {
      title: "Implement Least Privilege Access",
      description: "Grant users and administrators only the permissions they need to perform their job functions.",
      command: `# PowerShell script to audit group memberships
function Get-ADNestedGroupMembers {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )
    
    $members = Get-ADGroupMember -Identity $GroupName
    foreach ($member in $members) {
        if ($member.objectClass -eq "group") {
            Get-ADNestedGroupMembers -GroupName $member.Name
        } else {
            Get-ADUser -Identity $member.SamAccountName -Properties SamAccountName, Enabled, Title, Department |
                Select-Object SamAccountName, Enabled, Title, Department
        }
    }
}

# Check privileged group memberships
Get-ADNestedGroupMembers -GroupName "Domain Admins" | Format-Table -AutoSize`,
    },
    {
      title: "Secure Domain Controllers",
      description: "Implement strict security controls on domain controllers to protect the AD database.",
      command: `# PowerShell script to check DC security settings
$DCs = Get-ADDomainController -Filter *
foreach ($DC in $DCs) {
    Write-Host "Checking security settings for $($DC.Name)" -ForegroundColor Green
    
    # Check OS version and patches
    $OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $DC.Name
    Write-Host "OS Version: $($OS.Caption) $($OS.Version)" -ForegroundColor Yellow
    
    # Check services running
    $services = Get-Service -ComputerName $DC.Name | Where-Object { $_.Status -eq "Running" }
    Write-Host "Running services count: $($services.Count)" -ForegroundColor Yellow
    
    # Check firewall status
    $firewall = Invoke-Command -ComputerName $DC.Name -ScriptBlock { Get-NetFirewallProfile }
    Write-Host "Firewall status: Domain=$($firewall[0].Enabled), Private=$($firewall[1].Enabled), Public=$($firewall[2].Enabled)" -ForegroundColor Yellow
}`,
    },
    {
      title: "Implement Strong Authentication Policies",
      description: "Enforce multi-factor authentication and strong password policies.",
      command: `# PowerShell script to check password policy
$domain = Get-ADDomain
$policy = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot

Write-Host "Current Password Policy:" -ForegroundColor Green
Write-Host "Minimum Password Length: $($policy.MinPasswordLength)" -ForegroundColor Yellow
Write-Host "Password History Count: $($policy.PasswordHistoryCount)" -ForegroundColor Yellow
Write-Host "Lockout Threshold: $($policy.LockoutThreshold)" -ForegroundColor Yellow
Write-Host "Lockout Duration: $($policy.LockoutDuration)" -ForegroundColor Yellow
Write-Host "Password Complexity Enabled: $($policy.ComplexityEnabled)" -ForegroundColor Yellow

# Check for accounts with old passwords
$oldPasswordThreshold = (Get-Date).AddDays(-90)
$usersWithOldPasswords = Get-ADUser -Filter {Enabled -eq $true -and PasswordLastSet -lt $oldPasswordThreshold} -Properties PasswordLastSet |
    Select-Object SamAccountName, PasswordLastSet

Write-Host "Users with passwords older than 90 days: $($usersWithOldPasswords.Count)" -ForegroundColor Yellow`,
    },
    {
      title: "Monitor and Audit AD Activities",
      description: "Implement comprehensive logging and monitoring of Active Directory events.",
      command: `# PowerShell script to configure advanced audit policy
# Enable detailed audit policies
$auditCategories = @(
    "Account Logon",
    "Account Management",
    "Directory Service Access",
    "Logon/Logoff",
    "Object Access",
    "Policy Change",
    "Privilege Use",
    "System"
)

foreach ($category in $auditCategories) {
    auditpol /set /category:"$category" /success:enable /failure:enable
}

# Check current audit policy
auditpol /get /category:*

# Configure event log sizes
wevtutil sl Security /ms:1073741824
wevtutil sl System /ms:1073741824
wevtutil sl Application /ms:1073741824`,
    },
    {
      title: "Protect Against Credential Theft",
      description: "Implement measures to prevent credential theft and misuse.",
      command: `# PowerShell script to enable credential guard and other protections
# Check if Credential Guard is running
$deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

if ($deviceGuard.SecurityServicesRunning -contains 1) {
    Write-Host "Credential Guard is running" -ForegroundColor Green
} else {
    Write-Host "Credential Guard is not running" -ForegroundColor Red
}

# Enable LSASS protection
$lsassProtectionKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lsassProtectionValue = (Get-ItemProperty -Path $lsassProtectionKey).RunAsPPL

if ($lsassProtectionValue -eq 1) {
    Write-Host "LSASS Protection is enabled" -ForegroundColor Green
} else {
    Write-Host "LSASS Protection is not enabled" -ForegroundColor Red
    # Enable LSASS Protection
    Set-ItemProperty -Path $lsassProtectionKey -Name "RunAsPPL" -Value 1 -Type DWORD
}`,
    },
  ],
  tools: [
    {
      name: "Microsoft Active Directory Administrative Center",
      description: "Built-in tool for managing and monitoring Active Directory",
      usage: `# Launch from PowerShell
dsac.exe

# Or from Start Menu
# Administrative Tools > Active Directory Administrative Center`,
    },
    {
      name: "Active Directory Users and Computers (ADUC)",
      description: "Primary tool for managing users, groups, computers, and OUs",
      usage: `# Launch from PowerShell
dsa.msc

# Or from Start Menu
# Administrative Tools > Active Directory Users and Computers`,
    },
    {
      name: "Group Policy Management Console (GPMC)",
      description: "Tool for managing Group Policy Objects in Active Directory",
      usage: `# Launch from PowerShell
gpmc.msc

# Or from Start Menu
# Administrative Tools > Group Policy Management`,
    },
    {
      name: "BloodHound",
      description: "Tool for finding attack paths in Active Directory environments",
      usage: `# Run collector (SharpHound)
Import-Module SharpHound.ps1
Invoke-BloodHound -CollectionMethod All

# Analyze data in BloodHound UI
# Launch BloodHound and import data`,
    },
    {
      name: "PingCastle",
      description: "Tool for auditing the security level of Active Directory",
      usage: `# Run basic audit
PingCastle.exe --healthcheck

# Generate report
PingCastle.exe --healthcheck --server DC01.domain.local --output HTML`,
    },
    {
      name: "Microsoft Security Compliance Toolkit",
      description: "Set of tools for configuring and analyzing security baselines in AD environments",
      usage: `# Use the included tools:
# - Policy Analyzer
# - Local Group Policy Object (LGPO) Tool
# - Security Compliance Toolkit (SCT)

# Apply baseline GPOs
LGPO.exe /g "C:\\Baselines\\Domain Controller\\GPOs"`,
    },
    {
      name: "AD ACL Scanner",
      description: "Tool for creating reports of access control lists in Active Directory",
      usage: `# Launch the tool
ADACLScan.ps1

# Scan specific OU
.\ADACLScan.ps1 -Base "OU=Users,DC=domain,DC=local" -Output HTML -Show`,
    },
    {
      name: "Microsoft Advanced Threat Analytics (ATA)",
      description: "Platform for detecting and investigating advanced attacks and insider threats",
      usage: `# Access via web interface
https://ata-center.domain.local

# Review security alerts and suspicious activities
# Configure detection settings`,
    },
  ],
  pitfalls: [
    "Using the same administrative accounts for multiple purposes and tiers",
    "Granting excessive permissions to users and service accounts",
    "Neglecting to monitor and audit critical AD events",
    "Using weak or default passwords for privileged accounts",
    "Not implementing proper account lifecycle management",
    "Failing to secure domain controllers with appropriate controls",
    "Not implementing proper network segmentation for AD services",
    "Neglecting regular security assessments and penetration testing",
    "Allowing direct internet access from domain controllers",
    "Not having a proper disaster recovery plan for AD",
  ],
  references: [
    {
      title: "Microsoft Security Baselines for Active Directory",
      url: "https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines",
    },
    {
      title: "NIST SP 800-53: Security Controls for Active Directory",
      url: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    },
    {
      title: "CIS Benchmarks for Active Directory",
      url: "https://www.cisecurity.org/benchmark/microsoft_windows_server/",
    },
    {
      title: "SANS Securing Active Directory Guide",
      url: "https://www.sans.org/security-resources/posters/securing-active-directory/215/download",
    },
    {
      title: "Microsoft Best Practices for Securing Active Directory",
      url: "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory",
    },
  ],
}

export default function ActiveDirectoryPage() {
  const { title, tagline, icon: Icon, overview, bestPractices, tools, pitfalls, references } = activeDirectory

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
                  <CardDescription>Understanding Active Directory security fundamentals</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>{overview}</p>

                  <div className="grid gap-4 md:grid-cols-3">
                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Users className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Identity Management</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Secure user accounts, groups, and permissions with proper lifecycle management and least
                          privilege principles.
                        </p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <FileText className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Group Policy</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Implement secure configurations across your environment using Group Policy Objects (GPOs).
                        </p>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="p-4">
                        <div className="flex items-center gap-2">
                          <Database className="h-5 w-5 text-primary" />
                          <CardTitle className="text-base">Infrastructure</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4 pt-0">
                        <p className="text-sm">
                          Protect domain controllers and AD database from unauthorized access and tampering.
                        </p>
                      </CardContent>
                    </Card>
                  </div>

                  <Alert>
                    <Shield className="h-4 w-4" />
                    <AlertTitle>Critical Infrastructure</AlertTitle>
                    <AlertDescription>
                      Active Directory is the backbone of authentication and authorization in most enterprise
                      environments. A compromise of AD can lead to complete domain control by attackers. Implement
                      defense in depth to protect this critical infrastructure.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="best-practices" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle>Best Practices</CardTitle>
                  <CardDescription>Essential security configurations for Active Directory</CardDescription>
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
                  <CardDescription>Software to help secure and audit Active Directory</CardDescription>
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
                  <CardDescription>Sample configurations for securing Active Directory</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <h3 className="text-lg font-medium mb-2">Secure Domain Controller GPO Settings</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# PowerShell script to export and document DC security settings

# Create a new GPO for Domain Controllers
New-GPO -Name "DC Security Settings" -Comment "Security settings for all Domain Controllers"

# Configure User Rights Assignment
$gpo = Get-GPO -Name "DC Security Settings"
$domain = Get-ADDomain
$domainName = $domain.DNSRoot

# Set User Rights Assignment
$userRights = @{
    "SeBackupPrivilege" = "Backup Operators,Administrators"
    "SeDebugPrivilege" = "Administrators"
    "SeDenyNetworkLogonRight" = "Guests,NT AUTHORITY\\Local account"
    "SeDenyRemoteInteractiveLogonRight" = "Guests,NT AUTHORITY\\Local account"
    "SeRemoteInteractiveLogonRight" = "Administrators,Remote Desktop Users"
    "SeRestorePrivilege" = "Backup Operators,Administrators"
    "SeTakeOwnershipPrivilege" = "Administrators"
}

foreach ($right in $userRights.Keys) {
    Set-GPRegistryValue -Name $gpo.DisplayName -Key "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" -ValueName $right -Type MultiString -Value $userRights[$right].Split(",")
}

# Configure Security Options
$securityOptions = @{
    "Microsoft network server: Digitally sign communications (always)" = 1
    "Microsoft network server: Digitally sign communications (if client agrees)" = 1
    "Network security: LDAP client signing requirements" = 2
    "Network security: Minimum session security for NTLM SSP based clients" = 537395200
    "Network security: Minimum session security for NTLM SSP based servers" = 537395200
}

foreach ($option in $securityOptions.Keys) {
    Set-GPRegistryValue -Name $gpo.DisplayName -Key "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -ValueName $option -Type DWord -Value $securityOptions[$option]
}

# Configure Advanced Audit Policy
$auditPolicies = @{
    "Account Logon" = "Success,Failure"
    "Account Management" = "Success,Failure"
    "Directory Service Access" = "Success,Failure"
    "Logon/Logoff" = "Success,Failure"
    "Object Access" = "Success,Failure"
    "Policy Change" = "Success,Failure"
    "Privilege Use" = "Success,Failure"
    "System" = "Success,Failure"
}

foreach ($policy in $auditPolicies.Keys) {
    Set-GPRegistryValue -Name $gpo.DisplayName -Key "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" -ValueName $policy -Type String -Value $auditPolicies[$policy]
}

# Link the GPO to the Domain Controllers OU
$dcOU = "OU=Domain Controllers," + $domain.DistinguishedName
New-GPLink -Name $gpo.DisplayName -Target $dcOU -Enforced Yes`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# PowerShell script to export and document DC security settings

# Create a new GPO for Domain Controllers
New-GPO -Name "DC Security Settings" -Comment "Security settings for all Domain Controllers"

# Configure User Rights Assignment
$gpo = Get-GPO -Name "DC Security Settings"
$domain = Get-ADDomain
$domainName = $domain.DNSRoot

# Set User Rights Assignment
$userRights = @{
    "SeBackupPrivilege" = "Backup Operators,Administrators"
    "SeDebugPrivilege" = "Administrators"
    "SeDenyNetworkLogonRight" = "Guests,NT AUTHORITY\\Local account"
    "SeDenyRemoteInteractiveLogonRight" = "Guests,NT AUTHORITY\\Local account"
    "SeRemoteInteractiveLogonRight" = "Administrators,Remote Desktop Users"
    "SeRestorePrivilege" = "Backup Operators,Administrators"
    "SeTakeOwnershipPrivilege" = "Administrators"
}

foreach ($right in $userRights.Keys) {
    Set-GPRegistryValue -Name $gpo.DisplayName -Key "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" -ValueName $right -Type MultiString -Value $userRights[$right].Split(",")
}

# Configure Security Options
$securityOptions = @{
    "Microsoft network server: Digitally sign communications (always)" = 1
    "Microsoft network server: Digitally sign communications (if client agrees)" = 1
    "Network security: LDAP client signing requirements" = 2
    "Network security: Minimum session security for NTLM SSP based clients" = 537395200
    "Network security: Minimum session security for NTLM SSP based servers" = 537395200
}

foreach ($option in $securityOptions.Keys) {
    Set-GPRegistryValue -Name $gpo.DisplayName -Key "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -ValueName $option -Type DWord -Value $securityOptions[$option]
}

# Configure Advanced Audit Policy
$auditPolicies = @{
    "Account Logon" = "Success,Failure"
    "Account Management" = "Success,Failure"
    "Directory Service Access" = "Success,Failure"
    "Logon/Logoff" = "Success,Failure"
    "Object Access" = "Success,Failure"
    "Policy Change" = "Success,Failure"
    "Privilege Use" = "Success,Failure"
    "System" = "Success,Failure"
}

foreach ($policy in $auditPolicies.Keys) {
    Set-GPRegistryValue -Name $gpo.DisplayName -Key "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" -ValueName $policy -Type String -Value $auditPolicies[$policy]
}

# Link the GPO to the Domain Controllers OU
$dcOU = "OU=Domain Controllers," + $domain.DistinguishedName
New-GPLink -Name $gpo.DisplayName -Target $dcOU -Enforced Yes`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">Tiered Administrative Model Implementation</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# PowerShell script to implement tiered admin model

# Get the domain
$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName

# Create OUs for tiered administration
$tierOUs = @(
    "OU=Tier 0,OU=Admin,$domainDN",
    "OU=Tier 1,OU=Admin,$domainDN",
    "OU=Tier 2,OU=Admin,$domainDN",
    "OU=Admin,$domainDN"
)

# Create OUs if they don't exist
foreach ($ou in $tierOUs) {
    $ouName = $ou.Split(",")[0].Replace("OU=", "")
    $ouPath = $ou.Substring($ou.IndexOf(",") + 1)
    
    if (-not (Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$ou'" -ErrorAction SilentlyContinue)) {
        if ($ouName -eq "Admin") {
            New-ADOrganizationalUnit -Name $ouName -Path $domainDN -ProtectedFromAccidentalDeletion $true
        } else {
            New-ADOrganizationalUnit -Name $ouName -Path $ouPath -ProtectedFromAccidentalDeletion $true
        }
        Write-Host "Created OU: $ou" -ForegroundColor Green
    } else {
        Write-Host "OU already exists: $ou" -ForegroundColor Yellow
    }
}

# Create security groups for each tier
$tierGroups = @(
    @{Name = "Tier0-Admins"; Description = "Tier 0 Administrators with access to domain controllers and AD infrastructure"; Path = "OU=Tier 0,OU=Admin,$domainDN"},
    @{Name = "Tier1-Admins"; Description = "Tier 1 Administrators with access to server infrastructure"; Path = "OU=Tier 1,OU=Admin,$domainDN"},
    @{Name = "Tier2-Admins"; Description = "Tier 2 Administrators with access to workstations"; Path = "OU=Tier 2,OU=Admin,$domainDN"}
)

foreach ($group in $tierGroups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$($group.Name)'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $group.Name -SamAccountName $group.Name -GroupCategory Security -GroupScope Global -DisplayName $group.Name -Path $group.Path -Description $group.Description
        Write-Host "Created group: $($group.Name)" -ForegroundColor Green
    } else {
        Write-Host "Group already exists: $($group.Name)" -ForegroundColor Yellow
    }
}

# Create GPOs for each tier
$tierGPOs = @(
    @{Name = "Tier0-Security"; Description = "Security settings for Tier 0 administrators"},
    @{Name = "Tier1-Security"; Description = "Security settings for Tier 1 administrators"},
    @{Name = "Tier2-Security"; Description = "Security settings for Tier 2 administrators"}
)

foreach ($gpo in $tierGPOs) {
    if (-not (Get-GPO -Name $gpo.Name -ErrorAction SilentlyContinue)) {
        New-GPO -Name $gpo.Name -Comment $gpo.Description
        Write-Host "Created GPO: $($gpo.Name)" -ForegroundColor Green
    } else {
        Write-Host "GPO already exists: $($gpo.Name)" -ForegroundColor Yellow
    }
}

# Link GPOs to OUs
New-GPLink -Name "Tier0-Security" -Target "OU=Tier 0,OU=Admin,$domainDN" -Enforced Yes
New-GPLink -Name "Tier1-Security" -Target "OU=Tier 1,OU=Admin,$domainDN" -Enforced Yes
New-GPLink -Name "Tier2-Security" -Target "OU=Tier 2,OU=Admin,$domainDN" -Enforced Yes

Write-Host "Tiered administration model implemented successfully!" -Foregroun  -Enforced Yes

Write-Host "Tiered administration model implemented successfully!" -ForegroundColor Green`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# PowerShell script to implement tiered admin model

# Get the domain
$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName

# Create OUs for tiered administration
$tierOUs = @(
    "OU=Tier 0,OU=Admin,$domainDN",
    "OU=Tier 1,OU=Admin,$domainDN",
    "OU=Tier 2,OU=Admin,$domainDN",
    "OU=Admin,$domainDN"
)

# Create OUs if they don't exist
foreach ($ou in $tierOUs) {
    $ouName = $ou.Split(",")[0].Replace("OU=", "")
    $ouPath = $ou.Substring($ou.IndexOf(",") + 1)
    
    if (-not (Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$ou'" -ErrorAction SilentlyContinue)) {
        if ($ouName -eq "Admin") {
            New-ADOrganizationalUnit -Name $ouName -Path $domainDN -ProtectedFromAccidentalDeletion $true
        } else {
            New-ADOrganizationalUnit -Name $ouName -Path $ouPath -ProtectedFromAccidentalDeletion $true
        }
        Write-Host "Created OU: $ou" -ForegroundColor Green
    } else {
        Write-Host "OU already exists: $ou" -ForegroundColor Yellow
    }
}

# Create security groups for each tier
$tierGroups = @(
    @{Name = "Tier0-Admins"; Description = "Tier 0 Administrators with access to domain controllers and AD infrastructure"; Path = "OU=Tier 0,OU=Admin,$domainDN"},
    @{Name = "Tier1-Admins"; Description = "Tier 1 Administrators with access to server infrastructure"; Path = "OU=Tier 1,OU=Admin,$domainDN"},
    @{Name = "Tier2-Admins"; Description = "Tier 2 Administrators with access to workstations"; Path = "OU=Tier 2,OU=Admin,$domainDN"}
)

foreach ($group in $tierGroups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$($group.Name)'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $group.Name -SamAccountName $group.Name -GroupCategory Security -GroupScope Global -DisplayName $group.Name -Path $group.Path -Description $group.Description
        Write-Host "Created group: $($group.Name)" -ForegroundColor Green
    } else {
        Write-Host "Group already exists: $($group.Name)" -ForegroundColor Yellow
    }
}

# Create GPOs for each tier
$tierGPOs = @(
    @{Name = "Tier0-Security"; Description = "Security settings for Tier 0 administrators"},
    @{Name = "Tier1-Security"; Description = "Security settings for Tier 1 administrators"},
    @{Name = "Tier2-Security"; Description = "Security settings for Tier 2 administrators"}
)

foreach ($gpo in $tierGPOs) {
    if (-not (Get-GPO -Name $gpo.Name -ErrorAction SilentlyContinue)) {
        New-GPO -Name $gpo.Name -Comment $gpo.Description
        Write-Host "Created GPO: $($gpo.Name)" -ForegroundColor Green
    } else {
        Write-Host "GPO already exists: $($gpo.Name)" -ForegroundColor Yellow
    }
}

# Link GPOs to OUs
New-GPLink -Name "Tier0-Security" -Target "OU=Tier 0,OU=Admin,$domainDN" -Enforced Yes
New-GPLink -Name "Tier1-Security" -Target "OU=Tier 1,OU=Admin,$domainDN" -Enforced Yes
New-GPLink -Name "Tier2-Security" -Target "OU=Tier 2,OU=Admin,$domainDN" -Enforced Yes

Write-Host "Tiered administration model implemented successfully!" -ForegroundColor Green`)
                        }
                      >
                        <Copy className="h-4 w-4" />
                        <span className="sr-only">Copy code</span>
                      </Button>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-lg font-medium mb-2">Secure LDAP Configuration</h3>
                    <div className="relative">
                      <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm">
                        <code>
                          {`# PowerShell script to configure secure LDAP (LDAPS)

# Check if LDAPS is already configured
$ldapsPort = 636
$ldapsTest = Test-NetConnection -ComputerName localhost -Port $ldapsPort -InformationLevel Quiet

if ($ldapsTest) {
    Write-Host "LDAPS is already configured and listening on port $ldapsPort" -ForegroundColor Green
} else {
    Write-Host "LDAPS is not configured or not listening on port $ldapsPort" -ForegroundColor Yellow
}

# Check for existing certificates
$certs = Get-ChildItem -Path Cert:\\LocalMachine\\My | Where-Object { $_.Subject -like "*DC=*" }

if ($certs.Count -gt 0) {
    Write-Host "Found $($certs.Count) domain controller certificates:" -ForegroundColor Green
    $certs | ForEach-Object {
        Write-Host "  Subject: $($_.Subject)" -ForegroundColor Green
        Write-Host "  Thumbprint: $($_.Thumbprint)" -ForegroundColor Green
        Write-Host "  Valid until: $($_.NotAfter)" -ForegroundColor Green
    }
} else {
    Write-Host "No domain controller certificates found. You need to install a certificate for LDAPS." -ForegroundColor Yellow
    
    # Generate certificate request
    Write-Host "Generating certificate request..." -ForegroundColor Yellow
    
    $domain = Get-ADDomain
    $domainName = $domain.DNSRoot
    $dcName = $env:COMPUTERNAME
    
    $infFile = @"
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=$dcName.$domainName"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.1 ; Server Authentication
OID = 1.3.6.1.5.5.7.3.2 ; Client Authentication

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$dcName.$domainName&"
_continue_ = "dns=$dcName&"
"@
    
    $infFile | Out-File -FilePath "$env:TEMP\ldaps.inf" -Force
    
    # Create certificate request
    certreq -new "$env:TEMP\ldaps.inf" "$env:TEMP\ldaps.req"
    
    Write-Host "Certificate request generated at $env:TEMP\ldaps.req" -ForegroundColor Green
    Write-Host "Submit this request to your Certificate Authority, then install the certificate." -ForegroundColor Yellow
}

# Configure LDAP Server signing and channel binding
$ldapRegPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"

# Check current settings
$ldapSigningValue = (Get-ItemProperty -Path $ldapRegPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue).LDAPServerIntegrity
$ldapChannelBindingValue = (Get-ItemProperty -Path $ldapRegPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue).LdapEnforceChannelBinding

# Set LDAP Server signing to required (value 2)
if ($ldapSigningValue -ne 2) {
    Set-ItemProperty -Path $ldapRegPath -Name "LDAPServerIntegrity" -Value 2 -Type DWord
    Write-Host "LDAP Server signing set to required (2)" -ForegroundColor Green
} else {
    Write-Host "LDAP Server signing already set to required (2)" -ForegroundColor Green
}

# Set LDAP Channel Binding to required (value 2)
if ($ldapChannelBindingValue -ne 2) {
    Set-ItemProperty -Path $ldapRegPath -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord
    Write-Host "LDAP Channel Binding set to required (2)" -ForegroundColor Green
} else {
    Write-Host "LDAP Channel Binding already set to required (2)" -ForegroundColor Green
}

Write-Host "LDAPS configuration completed. A restart of the domain controller may be required for changes to take effect." -ForegroundColor Yellow`}
                        </code>
                      </pre>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="absolute top-2 right-2"
                        onClick={() =>
                          navigator.clipboard.writeText(`# PowerShell script to configure secure LDAP (LDAPS)

# Check if LDAPS is already configured
$ldapsPort = 636
$ldapsTest = Test-NetConnection -ComputerName localhost -Port $ldapsPort -InformationLevel Quiet

if ($ldapsTest) {
    Write-Host "LDAPS is already configured and listening on port $ldapsPort" -ForegroundColor Green
} else {
    Write-Host "LDAPS is not configured or not listening on port $ldapsPort" -ForegroundColor Yellow
}

# Check for existing certificates
$certs = Get-ChildItem -Path Cert:\\LocalMachine\\My | Where-Object { $_.Subject -like "*DC=*" }

if ($certs.Count -gt 0) {
    Write-Host "Found $($certs.Count) domain controller certificates:" -ForegroundColor Green
    $certs | ForEach-Object {
        Write-Host "  Subject: $($_.Subject)" -ForegroundColor Green
        Write-Host "  Thumbprint: $($_.Thumbprint)" -ForegroundColor Green
        Write-Host "  Valid until: $($_.NotAfter)" -ForegroundColor Green
    }
} else {
    Write-Host "No domain controller certificates found. You need to install a certificate for LDAPS." -ForegroundColor Yellow
    
    # Generate certificate request
    Write-Host "Generating certificate request..." -ForegroundColor Yellow
    
    $domain = Get-ADDomain
    $domainName = $domain.DNSRoot
    $dcName = $env:COMPUTERNAME
    
    $infFile = @"
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=$dcName.$domainName"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.1 ; Server Authentication
OID = 1.3.6.1.5.5.7.3.2 ; Client Authentication

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$dcName.$domainName&"
_continue_ = "dns=$dcName&"
"@
    
    $infFile | Out-File -FilePath "$env:TEMP\ldaps.inf" -Force
    
    # Create certificate request
    certreq -new "$env:TEMP\ldaps.inf" "$env:TEMP\ldaps.req"
    
    Write-Host "Certificate request generated at $env:TEMP\ldaps.req" -ForegroundColor Green
    Write-Host "Submit this request to your Certificate Authority, then install the certificate." -ForegroundColor Yellow
}

# Configure LDAP Server signing and channel binding
$ldapRegPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"

# Check current settings
$ldapSigningValue = (Get-ItemProperty -Path $ldapRegPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue).LDAPServerIntegrity
$ldapChannelBindingValue = (Get-ItemProperty -Path $ldapRegPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue).LdapEnforceChannelBinding

# Set LDAP Server signing to required (value 2)
if ($ldapSigningValue -ne 2) {
    Set-ItemProperty -Path $ldapRegPath -Name "LDAPServerIntegrity" -Value 2 -Type DWord
    Write-Host "LDAP Server signing set to required (2)" -ForegroundColor Green
} else {
    Write-Host "LDAP Server signing already set to required (2)" -ForegroundColor Green
}

# Set LDAP Channel Binding to required (value 2)
if ($ldapChannelBindingValue -ne 2) {
    Set-ItemProperty -Path $ldapRegPath -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord
    Write-Host "LDAP Channel Binding set to required (2)" -ForegroundColor Green
} else {
    Write-Host "LDAP Channel Binding already set to required (2)" -ForegroundColor Green
}

Write-Host "LDAPS configuration completed. A restart of the domain controller may be required for changes to take effect." -ForegroundColor Yellow`)
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
                  <CardDescription>Mistakes to avoid when securing Active Directory</CardDescription>
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
                  <Link href="/category/windows-os" className="block text-sm hover:underline">
                    Windows OS
                  </Link>
                  <Link href="/category/networking-architecture" className="block text-sm hover:underline">
                    Networking Architecture
                  </Link>
                  <Link href="/category/auditing-monitoring" className="block text-sm hover:underline">
                    Auditing & Monitoring
                  </Link>
                </nav>
              </CardContent>
            </Card>

            <Alert className="mt-6">
              <Key className="h-4 w-4" />
              <AlertTitle>Privileged Access</AlertTitle>
              <AlertDescription className="text-sm">
                Remember that compromised administrative credentials can lead to complete domain compromise. Always use
                dedicated, secured workstations for AD administration.
              </AlertDescription>
            </Alert>
          </div>
        </div>
      </div>
    </div>
  )
}

