import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/**
 * Lightweight edge middleware — checks for NextAuth session token cookie.
 * Does NOT import the full auth config (Prisma/bcrypt) to stay under
 * Vercel's 1 MB Edge Function size limit.
 */
export function middleware(request: NextRequest) {
  const token =
    request.cookies.get("authjs.session-token")?.value ??
    request.cookies.get("__Secure-authjs.session-token")?.value;

  const isOnLogin = request.nextUrl.pathname === "/login";

  if (!token && !isOnLogin) {
    const loginUrl = new URL("/login", request.url);
    return NextResponse.redirect(loginUrl);
  }

  if (token && isOnLogin) {
    return NextResponse.redirect(new URL("/", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/((?!api/auth|_next/static|_next/image|favicon\\.ico).*)",
  ],
};
