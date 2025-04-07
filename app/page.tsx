'use client'
import Link from "next/link"
import {
  Shield,
  Server,
  LaptopIcon as Linux,
  ComputerIcon as Windows,
  Users,
  Network,
  Cloud,
  BarChart,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"

export default function Home() {
  const categories = [
    {
      title: "Networking Architecture",
      description: "Design secure network infrastructure with proper segmentation and defense in depth.",
      icon: Network,
      slug: "networking-architecture",
    },
    {
      title: "Linux OS",
      description: "Harden Linux systems against common vulnerabilities and attacks.",
      icon: Linux,
      slug: "linux-os",
    },
    {
      title: "Windows OS",
      description: "Secure Windows operating systems with best practices and tools.",
      icon: Windows,
      slug: "windows-os",
    },
    {
      title: "Active Directory",
      description: "Protect your directory services and identity management infrastructure.",
      icon: Users,
      slug: "active-directory",
    },
    {
      title: "Network Devices",
      description: "Secure routers, switches, and other network equipment.",
      icon: Server,
      slug: "network-devices",
    },
    {
      title: "Network Security",
      description: "Implement firewalls, IDS/IPS, and other security controls.",
      icon: Shield,
      slug: "network-security",
    },
    {
      title: "Virtualization & Containers",
      description: "Secure virtual machines, containers, and orchestration platforms.",
      icon: Server,
      slug: "virtualization-containers",
    },
    {
      title: "Cloud Security",
      description: "Protect cloud infrastructure and services across providers.",
      icon: Cloud,
      slug: "cloud-security",
    },
    {
      title: "Auditing & Monitoring",
      description: "Track system activities and detect security incidents.",
      icon: BarChart,
      slug: "auditing-monitoring",
    },
  ]

  return (
    <div className="flex flex-col min-h-screen">
      <main className="flex-1">
        <section className="w-full py-12 md:py-24 lg:py-32 bg-muted">
          <div className="container px-4 md:px-6">
            <div className="flex flex-col items-center justify-center space-y-4 text-center">
              <div className="space-y-2">
                <h1 className="text-3xl font-bold tracking-tighter sm:text-4xl md:text-5xl lg:text-6xl">
                  Secure Systems Start Here
                </h1>
                <p className="mx-auto max-w-[700px] text-muted-foreground md:text-xl">
                  A comprehensive guide to hardening your systems against security threats.
                </p>
              </div>
              <div className="space-x-4">
                <Link href="/category/linux-os">
                  <Button>Get Started</Button>
                </Link>
                <Link href="/tools">
                  <Button variant="outline">View Tools</Button>
                </Link>
              </div>
            </div>
          </div>
        </section>

        <section className="w-full py-12 md:py-24 lg:py-32">
          <div className="container px-4 md:px-6">
            <div className="flex flex-col items-center justify-center space-y-4 text-center">
              <div className="space-y-2">
                <h2 className="text-3xl font-bold tracking-tighter sm:text-4xl md:text-5xl">Security Hardening</h2>
                <p className="mx-auto max-w-[700px] text-muted-foreground md:text-xl">
                  Security hardening is the process of reducing vulnerabilities by configuring systems with security
                  controls, minimizing attack surfaces, and eliminating potential pathways for attackers. This
                  comprehensive guide covers best practices across various platforms and technologies.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-6 mt-12 md:grid-cols-2 lg:grid-cols-3">
              {categories.map((category) => (
                <Link key={category.slug} href={`/category/${category.slug}`} className="block">
                  <Card className="h-full transition-colors hover:border-primary">
                    <CardHeader className="flex flex-row items-center gap-4">
                      <category.icon className="h-8 w-8" />
                      <CardTitle>{category.title}</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <CardDescription className="text-base">{category.description}</CardDescription>
                    </CardContent>
                    <CardFooter>
                      <Button variant="ghost" className="w-full justify-start">
                        Learn more
                        <span className="sr-only">Learn more about {category.title}</span>
                      </Button>
                    </CardFooter>
                  </Card>
                </Link>
              ))}
            </div>
          </div>
        </section>
      </main>
    </div>
  )
}

