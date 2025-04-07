import Link from "next/link"
import { Shield } from "lucide-react"

export function MainNav() {
  return (
    <div className="flex gap-6 md:gap-10">
      <Link href="/" className="flex items-center space-x-2">
        <Shield className="h-6 w-6" />
        <span className="inline-block font-bold">Get Hard Security</span>
      </Link>
      <nav className="flex gap-6">
        <Link href="/category/linux-os" className="flex items-center text-sm font-medium text-muted-foreground">
          Linux
        </Link>
        <Link href="/category/windows-os" className="flex items-center text-sm font-medium text-muted-foreground">
          Windows
        </Link>
        <Link href="/category/cloud-security" className="flex items-center text-sm font-medium text-muted-foreground">
          Cloud
        </Link>
        <Link href="/category/networking-architecture" className="flex items-center text-sm font-medium text-muted-foreground">
          Net Arch
        </Link>
        {/* <Link href="/category/network-devices" className="flex items-center text-sm font-medium text-muted-foreground">
          Net Device
        </Link> */}
        <Link href="/category/network-security" className="flex items-center text-sm font-medium text-muted-foreground">
          Net Sec
        </Link>
        <Link href="/category/active-directory" className="flex items-center text-sm font-medium text-muted-foreground">
          Active Dir
        </Link>
        <Link href="/category/virtualization-containers" className="flex items-center text-sm font-medium text-muted-foreground">
          VM + Containers
        </Link>
        <Link href="/category/auditing-monitoring" className="flex items-center text-sm font-medium text-muted-foreground">
          Monitoring
        </Link>
      </nav>
    </div>
  )
}

