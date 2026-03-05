import type { NextConfig } from 'next';

const config: NextConfig = {
  serverExternalPackages: ['@vulnhunter/core', '@vulnhunter/scanner', '@vulnhunter/reporter'],
};

export default config;
