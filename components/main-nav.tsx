import Link from "next/link"
import { Shield } from "lucide-react"

export function MainNav() {
  return (
    <div className="flex gap-6 md:gap-10">
      <Link href="/" className="flex items-center space-x-2">
        <Shield className="h-6 w-6" />
        <span className="inline-block font-bold">Security Hardening Tool</span>
      </Link>
      <nav className="flex gap-6">
        <Link href="/category/linux-os" className="flex items-center text-sm font-medium text-muted-foreground">
          Linux OS
        </Link>
        <Link href="/category/windows-os" className="flex items-center text-sm font-medium text-muted-foreground">
          Windows OS
        </Link>
        <Link href="/category/cloud-security" className="flex items-center text-sm font-medium text-muted-foreground">
          Cloud
        </Link>
      </nav>
    </div>
  )
}

