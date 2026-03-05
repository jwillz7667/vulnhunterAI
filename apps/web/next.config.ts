import type { NextConfig } from 'next';

const config: NextConfig = {
  output: 'standalone',
  serverExternalPackages: ['@vulnhunter/core', '@vulnhunter/scanner', '@vulnhunter/reporter'],
};

export default config;
