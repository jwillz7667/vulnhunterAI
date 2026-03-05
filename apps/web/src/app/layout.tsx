import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { AuthSessionProvider } from '@/components/providers/session-provider';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
});

export const metadata: Metadata = {
  title: 'VulnHunter AI - Autonomous Security Research Platform',
  description:
    'AI-powered vulnerability discovery, exploitation, and reporting platform for security researchers and bug bounty hunters.',
  icons: {
    icon: '/favicon.ico',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.variable} font-sans`}>
        <AuthSessionProvider>{children}</AuthSessionProvider>
      </body>
    </html>
  );
}
