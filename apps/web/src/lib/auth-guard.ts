import { auth } from "@/lib/auth";
import { NextResponse } from "next/server";
import type { Session } from "next-auth";

export async function getAuthSession() {
  const session = await auth();
  if (!session?.user?.id) {
    return {
      session: null as unknown as Session,
      error: NextResponse.json({ error: "Unauthorized" }, { status: 401 }),
    };
  }
  return { session, error: null };
}

export function isAdmin(session: Session): boolean {
  return session.user.role === "ADMIN";
}

/** Returns a Prisma `where` filter scoped to the current user. Admins see all. */
export function tenantFilter(session: Session): { userId?: string } {
  if (isAdmin(session)) return {};
  return { userId: session.user.id };
}

/** For models accessed via Scan relation (Vulnerability, ExploitChain). */
export function scanTenantFilter(session: Session): {
  scan?: { userId: string };
} {
  if (isAdmin(session)) return {};
  return { scan: { userId: session.user.id } };
}
