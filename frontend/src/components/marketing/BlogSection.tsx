import Link from "next/link";

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

export default function BlogSection() {
  return (
    <section className="blog-section" aria-labelledby="blog-section-heading">
      <div className="blog-section-inner">
        {/* Section header */}
        <header className="blog-header">
          <div className="blog-header-text">
            <p className="blog-eyebrow" aria-hidden="true">FROM THE BLOG</p>
            <h2 id="blog-section-heading" className="blog-heading">
              Built for developers who care about code quality
            </h2>
            <p className="blog-subheading">
              Deep dives, best practices, and engineering notes from the DevAnalyzeX team.
            </p>
          </div>
          <Link
            href="/blog"
            className="blog-view-all"
            aria-label="View all blog articles"
          >
            View all articles <span aria-hidden="true">→</span>
          </Link>
        </header>

        {/* Cards grid */}
        <ul className="blog-grid" role="list">
          {POSTS.map((post) => (
            <li key={post.slug} className="blog-card-wrapper">
              <article className="blog-card">
                <div className="blog-card-top">
                  <span className="blog-category" aria-label={`Category: ${post.category}`}>
                    {post.category}
                  </span>
                  <h3 className="blog-title">{post.title}</h3>
                  <p className="blog-description">{post.description}</p>
                </div>

                <footer className="blog-card-footer">
                  <div className="blog-meta">
                    <time dateTime={post.date} className="blog-date">
                      {post.date}
                    </time>
                    <span className="blog-dot" aria-hidden="true">·</span>
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
    </section>
  );
}
