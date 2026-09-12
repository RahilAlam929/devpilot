import Link from "next/link";

const GITHUB_URL = "https://github.com/RahilAlam929/devanalyzex";

type NavLink =
  | { label: string; href: string; external?: false }
  | { label: string; href: string; external: true };

const NAV_GROUPS: { label: string; links: NavLink[] }[] = [
  {
    label: "Product",
    links: [
      { label: "Dashboard", href: "/dashboard" },
      { label: "Projects", href: "/projects" },
      { label: "Repositories", href: "/repositories" },
      { label: "Scans", href: "/scans" },
      { label: "Findings", href: "/findings" },
    ],
  },
  {
    label: "Resources",
    links: [
      { label: "Blog", href: "/blog" },
      { label: "Docs", href: GITHUB_URL, external: true },
      { label: "GitHub", href: GITHUB_URL, external: true },
    ],
  },
  {
    label: "Company",
    links: [
      { label: "About", href: "/about" },
      { label: "Contact", href: "/contact" },
    ],
  },
];

export default function SiteFooter() {
  const year = new Date().getFullYear();

  return (
    <footer className="site-footer" aria-label="Site footer">
      <div className="site-footer-inner">
        {/* Top: brand column + nav groups */}
        <div className="footer-top">
          {/* Brand */}
          <div className="footer-brand-block">
            <Link href="/" className="footer-brand" aria-label="DevAnalyzeX home">
              <div className="footer-brand-mark" aria-hidden="true">D</div>
              <span className="footer-brand-name">DevAnalyzeX</span>
            </Link>

            <p className="footer-brand-desc">
              Static analysis and security intelligence for software repositories.
              Detect code quality, security, and maintainability issues — instantly.
            </p>

            <a
              href={GITHUB_URL}
              className="footer-social-link"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="DevAnalyzeX on GitHub (opens in a new tab)"
            >
              {/* GitHub mark SVG */}
              <svg
                className="footer-social-icon"
                viewBox="0 0 24 24"
                fill="currentColor"
                aria-hidden="true"
                width="16"
                height="16"
                focusable="false"
              >
                <path d="M12 2C6.477 2 2 6.484 2 12.021c0 4.428 2.865 8.184 6.839 9.504.5.092.682-.217.682-.483 0-.237-.009-.868-.013-1.703-2.782.605-3.369-1.342-3.369-1.342-.454-1.156-1.11-1.463-1.11-1.463-.908-.62.069-.608.069-.608 1.003.07 1.531 1.031 1.531 1.031.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482C19.138 20.2 22 16.447 22 12.021 22 6.484 17.522 2 12 2z" />
              </svg>
              GitHub
            </a>
          </div>

          {/* Navigation groups */}
          <nav aria-label="Footer navigation" className="footer-nav-wrapper">
            {NAV_GROUPS.map((group) => (
              <div key={group.label} className="footer-nav-group">
                <p className="footer-nav-label">{group.label}</p>
                <ul className="footer-nav-list">
                  {group.links.map((link) =>
                    link.external ? (
                      <li key={link.label}>
                        <a
                          href={link.href}
                          className="footer-nav-link"
                          target="_blank"
                          rel="noopener noreferrer"
                          aria-label={`${link.label} (opens in a new tab)`}
                        >
                          {link.label}
                        </a>
                      </li>
                    ) : (
                      <li key={link.label}>
                        <Link href={link.href} className="footer-nav-link">
                          {link.label}
                        </Link>
                      </li>
                    )
                  )}
                </ul>
              </div>
            ))}
          </nav>
        </div>

        <div className="footer-divider" role="separator" aria-hidden="true" />

        {/* Bottom bar */}
        <div className="footer-bottom">
          <p className="footer-copyright">
            © {year} DevAnalyzeX. All rights reserved.
          </p>
          <nav aria-label="Legal links" className="footer-legal-links">
            <Link href="/privacy" className="footer-legal-link">
              Privacy Policy
            </Link>
            <span className="footer-legal-sep" aria-hidden="true">·</span>
            <Link href="/terms" className="footer-legal-link">
              Terms of Service
            </Link>
          </nav>
        </div>
      </div>
    </footer>
  );
}
