import React from 'react'
import { DocsThemeConfig } from 'nextra-theme-docs'

const config: DocsThemeConfig = {
  logo: (
    <span style={{ fontWeight: 700, fontSize: '1.2rem' }}>
      <svg width="24" height="24" viewBox="0 0 100 100" style={{ marginRight: 8, verticalAlign: 'middle' }}>
        <defs>
          <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style={{ stopColor: '#0066FF', stopOpacity: 1 }} />
            <stop offset="100%" style={{ stopColor: '#00D4AA', stopOpacity: 1 }} />
          </linearGradient>
        </defs>
        <path d="M50 5 L90 20 L90 50 C90 75 70 90 50 95 C30 90 10 75 10 50 L10 20 Z" fill="url(#grad1)" />
        <rect x="35" y="45" width="30" height="25" rx="3" fill="white" />
        <path d="M40 45 L40 35 C40 27 44 22 50 22 C56 22 60 27 60 35 L60 45" fill="none" stroke="white" strokeWidth="5" strokeLinecap="round" />
        <circle cx="50" cy="55" r="4" fill="url(#grad1)" />
        <rect x="48" y="55" width="4" height="8" fill="url(#grad1)" />
      </svg>
      CryptoServe
    </span>
  ),
  project: {
    link: 'https://github.com/ecolibria/crypto-serve',
  },
  docsRepositoryBase: 'https://github.com/ecolibria/crypto-serve/tree/main/docs-site',
  useNextSeoProps() {
    return {
      titleTemplate: '%s – CryptoServe'
    }
  },
  head: (
    <>
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <meta property="og:title" content="CryptoServe" />
      <meta property="og:description" content="Cryptography-as-a-Service with Zero Configuration SDKs" />
      <link rel="icon" href="/crypto-serve/favicon.svg" type="image/svg+xml" />
    </>
  ),
  banner: {
    key: 'pqc-release',
    text: (
      <a href="/crypto-serve/concepts/post-quantum" target="_blank">
        🔐 CryptoServe now supports Post-Quantum Cryptography (ML-KEM, ML-DSA) →
      </a>
    ),
  },
  sidebar: {
    defaultMenuCollapseLevel: 1,
    toggleButton: true,
  },
  toc: {
    backToTop: true,
  },
  footer: {
    text: (
      <span>
        {new Date().getFullYear()} © CryptoServe Contributors. Built with Nextra.
      </span>
    ),
  },
  primaryHue: 210,
  primarySaturation: 100,
}

export default config
