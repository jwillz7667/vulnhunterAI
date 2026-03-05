"use client";

import { useState, useTransition } from "react";
import { Shield } from "lucide-react";
import { loginWithCredentials, loginWithGithub } from "./actions";

export function LoginForm() {
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  function handleCredentials(formData: FormData) {
    setError(null);
    startTransition(async () => {
      const result = await loginWithCredentials(formData);
      if (result?.error) setError(result.error);
    });
  }

  function handleGithub() {
    setError(null);
    startTransition(async () => {
      await loginWithGithub();
    });
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 px-4">
      <div className="w-full max-w-md">
        {/* Branding */}
        <div className="flex flex-col items-center mb-8">
          <div className="relative mb-4">
            <div className="h-14 w-14 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center shadow-glow-blue">
              <Shield className="h-8 w-8 text-white" />
            </div>
            <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 opacity-20 animate-ping" />
          </div>
          <h1 className="text-2xl font-bold gradient-text">VulnHunter</h1>
          <p className="text-sm text-slate-500 mt-1">
            AI Security Research Platform
          </p>
        </div>

        {/* Card */}
        <div className="glass-card p-8 rounded-2xl border border-slate-700/50">
          {/* GitHub OAuth */}
          <button
            type="button"
            onClick={handleGithub}
            disabled={isPending}
            className="w-full flex items-center justify-center gap-3 rounded-lg border border-slate-600/50 bg-slate-800/50 px-4 py-3 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-700/50 disabled:opacity-50"
          >
            <svg className="h-5 w-5" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
            </svg>
            Continue with GitHub
          </button>

          {/* Divider */}
          <div className="relative my-6">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-slate-700/50" />
            </div>
            <div className="relative flex justify-center text-xs">
              <span className="bg-slate-900 px-3 text-slate-500">
                or continue with email
              </span>
            </div>
          </div>

          {/* Credentials form */}
          <form action={handleCredentials} className="space-y-4">
            <div>
              <label
                htmlFor="email"
                className="block text-xs font-medium text-slate-400 mb-1.5"
              >
                Email
              </label>
              <input
                id="email"
                name="email"
                type="email"
                required
                autoComplete="email"
                className="w-full rounded-lg border border-slate-600/50 bg-slate-800/50 px-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 outline-none transition-colors focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/25"
                placeholder="you@example.com"
              />
            </div>
            <div>
              <label
                htmlFor="password"
                className="block text-xs font-medium text-slate-400 mb-1.5"
              >
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                required
                autoComplete="current-password"
                className="w-full rounded-lg border border-slate-600/50 bg-slate-800/50 px-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 outline-none transition-colors focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/25"
                placeholder="Enter your password"
              />
            </div>

            {error && (
              <div className="rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-2.5 text-sm text-red-400">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={isPending}
              className="w-full rounded-lg bg-gradient-to-r from-blue-500 to-cyan-500 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-blue-500/25 transition-all hover:shadow-blue-500/40 hover:brightness-110 disabled:opacity-50"
            >
              {isPending ? "Signing in..." : "Sign In"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
