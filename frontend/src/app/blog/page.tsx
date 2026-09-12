import type { Metadata } from "next";
import Link from "next/link";
import SiteFooter from "@/components/marketing/SiteFooter";

export const metadata: Metadata = {
  title: "Blog — DevAnalyzeX",
  description:
    "Deep dives, best practices, and engineering notes from the DevAnalyzeX team.",
};

interface BlogPost {
  category: string;
  title: string;
  description: string;
  date: string;
  readTime: string;
  slug: string;
}

const POSTS: BlogPost[] = [
  {
    category: "Engineering",
    title: "How DevAnalyzeX scans your repository",
    description:
      "A deep dive into the static analysis pipeline — from file discovery and language detection to severity-bucketed findings stored in PostgreSQL.",
    date: "Sep 10, 2026",
    readTime: "6 min read",
    slug: "how-devanalyzex-scans-your-repository",
  },
  {
    category: "Security",
    title: "Understanding security findings in your codebase",
    description:
      "Learn how to interpret high, medium, low, and info severity findings, and which categories of issues matter most for production systems.",
    date: "Sep 5, 2026",
    readTime: "8 min read",
    slug: "understanding-security-findings",
  },
  {
    category: "Best Practices",
    title: "Reducing false positives in code analysis",
    description:
      "Practical strategies for tuning your analysis rules, using suppression comments, and building a signal-over-noise workflow your team will trust.",
    date: "Aug 28, 2026",
    readTime: "5 min read",
    slug: "reducing-false-positives",
  },
  {
    category: "AI",
    title: "Building safer developer workflows with AI",
    description:
      "How LLM-assisted triage — verdict scoring, exploitability estimates, and remediation guidance — accelerates code review without replacing human judgment.",
    date: "Aug 20, 2026",
    readTime: "7 min read",
    slug: "safer-workflows-with-ai",
  },
];

export default function BlogPage() {
  return (
    <div className="blog-page-shell">
      {/* Skip to main content — keyboard users */}
      <a href="#main-content" className="skip-to-main">
        Skip to main content
      </a>

      {/* Top nav */}
      <header className="blog-page-nav">
        <div className="blog-page-nav-inner">
          <Link
            href="/"
            className="blog-page-brand"
            aria-label="DevAnalyzeX — go to home"
          >
            <div className="brand-mark blog-page-brand-mark" aria-hidden="true">
              D
            </div>
            <span className="brand-name">DevAnalyzeX</span>
          </Link>

          <nav aria-label="Site navigation" className="blog-page-nav-links">
            <Link
              href="/blog"
              className="blog-page-nav-link"
              aria-current="page"
            >
              Blog
            </Link>
            <Link href="/dashboard" className="blog-page-nav-link">
              Dashboard
            </Link>
            <Link
              href="/login"
              className="blog-page-nav-link blog-page-nav-cta"
            >
              Sign in
            </Link>
          </nav>
        </div>
      </header>

      {/* Hero */}
      <section className="blog-page-hero" aria-labelledby="blog-page-heading">
        <div className="blog-page-hero-inner">
          <p className="blog-eyebrow" aria-hidden="true">
            THE DEVANALYZEX BLOG
          </p>
          <h1 id="blog-page-heading" className="blog-page-title">
            Engineering, security,{" "}
            <span className="blog-page-title-break">and developer intelligence</span>
          </h1>
          <p className="blog-page-subtitle">
            Deep dives, best practices, and product notes from the team
            building DevAnalyzeX.
          </p>
        </div>
      </section>

      {/* Articles */}
      <main id="main-content" className="blog-page-main" tabIndex={-1}>
        <div className="blog-page-inner">
          <ul
            className="blog-page-grid"
            role="list"
            aria-label="Blog articles"
          >
            {POSTS.map((post) => (
              <li key={post.slug} className="blog-card-wrapper">
                <article className="blog-card blog-page-card">
                  <div className="blog-card-top">
                    <span
                      className="blog-category"
                      aria-label={`Category: ${post.category}`}
                    >
                      {post.category}
                    </span>
                    <h2 className="blog-title">{post.title}</h2>
                    <p className="blog-description">{post.description}</p>
                  </div>
                  <footer className="blog-card-footer">
                    <div className="blog-meta">
                      <time dateTime={post.date} className="blog-date">
                        {post.date}
                      </time>
                      <span className="blog-dot" aria-hidden="true">
                        ·
                      </span>
                      <span className="blog-read-time">{post.readTime}</span>
                    </div>
                    <Link
                      href={`/blog/${post.slug}`}
                      className="blog-read-link"
                      aria-label={`Read article: ${post.title}`}
                    >
                      Read article <span aria-hidden="true">→</span>
                    </Link>
                  </footer>
                </article>
              </li>
            ))}
          </ul>
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}
