import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  console.log("Seeding database...");

  // Create admin user
  const hashedPassword = await bcrypt.hash("12345678", 12);

  const admin = await prisma.user.upsert({
    where: { email: "admin7667@vulnhunter.local" },
    update: {},
    create: {
      name: "admin7667",
      email: "admin7667@vulnhunter.local",
      password: hashedPassword,
      role: "ADMIN",
      emailVerified: new Date(),
    },
  });

  console.log(`Admin user created: ${admin.name} (${admin.email})`);

  // Create sample targets
  const targets = await Promise.all([
    prisma.target.upsert({
      where: { id: "seed-target-1" },
      update: {},
      create: {
        id: "seed-target-1",
        name: "Example Corp",
        type: "DOMAIN",
        value: "example.com",
        scopeIncludes: ["*.example.com"],
        scopeExcludes: ["admin.example.com"],
        tags: ["production", "web"],
        metadata: { industry: "technology", tier: "primary" },
        userId: admin.id,
      },
    }),
    prisma.target.upsert({
      where: { id: "seed-target-2" },
      update: {},
      create: {
        id: "seed-target-2",
        name: "Test API",
        type: "URL",
        value: "https://api.testsite.local",
        scopeIncludes: ["https://api.testsite.local/*"],
        scopeExcludes: [],
        tags: ["api", "staging"],
        metadata: { stack: "Node.js, Express" },
        userId: admin.id,
      },
    }),
    prisma.target.upsert({
      where: { id: "seed-target-3" },
      update: {},
      create: {
        id: "seed-target-3",
        name: "Internal Network",
        type: "CIDR",
        value: "192.168.1.0/24",
        scopeIncludes: ["192.168.1.0/24"],
        scopeExcludes: ["192.168.1.1"],
        tags: ["internal", "network"],
        userId: admin.id,
      },
    }),
  ]);

  // Create sample scan templates
  await prisma.scanTemplate.upsert({
    where: { name: "quick-web-scan" },
    update: {},
    create: {
      name: "quick-web-scan",
      description: "Quick web vulnerability scan with common checks",
      config: {
        type: "WEB",
        modules: ["xss", "sqli", "cors", "headers"],
        options: { depth: 2, rateLimit: 10, timeout: 30000 },
      },
      isDefault: true,
      userId: admin.id,
    },
  });

  await prisma.scanTemplate.upsert({
    where: { name: "full-recon" },
    update: {},
    create: {
      name: "full-recon",
      description: "Full reconnaissance scan including subdomain enumeration, port scanning, and tech detection",
      config: {
        type: "RECON",
        modules: ["subdomain", "dns", "port-scan", "tech-detect", "crawler"],
        options: { depth: 5, rateLimit: 5, timeout: 120000 },
      },
      isDefault: false,
      userId: admin.id,
    },
  });

  console.log(`Seeded ${targets.length} targets and 2 scan templates.`);
}

main()
  .then(() => prisma.$disconnect())
  .catch((e) => {
    console.error(e);
    prisma.$disconnect();
    process.exit(1);
  });
