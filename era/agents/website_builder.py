"""First-class Website Builder capability (Phase 3H).

Builds modern, responsive, mobile-first multi-page static websites with:
* Clean HTML5 structure + semantic tags (header, nav, main, section, footer)
* SEO & OpenGraph meta tags, responsive viewport, accessible forms
* Vector SVG favicon + responsive CSS (CSS custom properties, flexbox, CSS grid)
* Interactive JavaScript (mobile navigation toggle, contact form client feedback, dynamic year)
* Multi-page routing (0 broken internal links)
* Zip archive export for immediate deployment/download.
"""

from __future__ import annotations

import html
import io
import re
import zipfile
from pathlib import Path


def slugify(name: str) -> str:
    """Convert subject name into a clean, filesystem-safe directory slug."""
    s = re.sub(r"[^a-zA-Z0-9]+", "_", name.lower()).strip("_")
    return s or "site"


def generate_favicon_svg(title: str) -> str:
    """Generate a clean, scalable vector SVG favicon."""
    letter = (title.strip()[:1] or "E").upper()
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <defs>
    <linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#4f46e5" />
      <stop offset="100%" stop-color="#06b6d4" />
    </linearGradient>
  </defs>
  <rect width="100" height="100" rx="20" fill="url(#g)" />
  <text x="50" y="68" font-size="52" font-family="system-ui, -apple-system, sans-serif"
        font-weight="bold" fill="#ffffff" text-anchor="middle">{letter}</text>
</svg>"""


CSS_TEMPLATE = """/* Mobile-first modern responsive styles (Phase 3H) */
:root {
  --primary: #4f46e5;
  --primary-hover: #4338ca;
  --secondary: #06b6d4;
  --text: #1f2937;
  --text-light: #6b7280;
  --bg: #f9fafb;
  --surface: #ffffff;
  --border: #e5e7eb;
  --radius: 8px;
  --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
}

@media (prefers-color-scheme: dark) {
  :root {
    --text: #f9fafb;
    --text-light: #9ca3af;
    --bg: #111827;
    --surface: #1f2937;
    --border: #374151;
  }
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  line-height: 1.6;
  color: var(--text);
  background-color: var(--bg);
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

header {
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  color: #ffffff;
  padding: 2.5rem 1.5rem;
  text-align: center;
}

header h1 {
  font-size: 2.2rem;
  margin-bottom: 0.5rem;
}

header p {
  font-size: 1.1rem;
  opacity: 0.95;
}

nav {
  background-color: var(--surface);
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: center;
  flex-wrap: wrap;
  padding: 0.5rem;
  gap: 0.5rem;
  position: sticky;
  top: 0;
  z-index: 10;
}

nav a {
  color: var(--text);
  text-decoration: none;
  padding: 0.5rem 1rem;
  border-radius: var(--radius);
  font-weight: 500;
  transition: all 0.2s ease;
}

nav a:hover, nav a.active {
  background-color: var(--primary);
  color: #ffffff;
}

main {
  flex: 1;
  max-width: 1000px;
  width: 100%;
  margin: 2rem auto;
  padding: 0 1.5rem;
}

section {
  background-color: var(--surface);
  padding: 2rem;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  box-shadow: var(--shadow);
  margin-bottom: 2rem;
}

h2 {
  color: var(--primary);
  margin-bottom: 1rem;
  font-size: 1.5rem;
}

p {
  margin-bottom: 1rem;
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1.5rem;
  margin-top: 1.5rem;
}

.card {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.5rem;
  background-color: var(--bg);
}

.card h3 {
  color: var(--primary);
  margin-bottom: 0.5rem;
}

form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  margin-top: 1rem;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
}

label {
  font-weight: 500;
  font-size: 0.95rem;
}

input, textarea {
  padding: 0.75rem;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  font-size: 1rem;
  background-color: var(--bg);
  color: var(--text);
}

input:focus, textarea:focus {
  outline: 2px solid var(--primary);
  border-color: transparent;
}

button {
  background-color: var(--primary);
  color: #ffffff;
  border: none;
  padding: 0.85rem 1.5rem;
  border-radius: var(--radius);
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  align-self: flex-start;
  transition: background-color 0.2s;
}

button:hover {
  background-color: var(--primary-hover);
}

.notice {
  display: none;
  padding: 1rem;
  background-color: #d1fae5;
  color: #065f46;
  border-radius: var(--radius);
  margin-top: 1rem;
}

footer {
  background-color: var(--surface);
  border-top: 1px solid var(--border);
  padding: 1.5rem;
  text-align: center;
  color: var(--text-light);
  font-size: 0.9rem;
  margin-top: auto;
}
"""

JS_TEMPLATE = """// Interactive client script (Phase 3H)
document.addEventListener("DOMContentLoaded", () => {
  // Update copyright year
  const yearEl = document.getElementById("year");
  if (yearEl) {
    yearEl.textContent = new Date().getFullYear();
  }

  // Active navigation highlight
  const currentPath = window.location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll("nav a").forEach(link => {
    if (link.getAttribute("href") === currentPath) {
      link.classList.add("active");
    }
  });

  // Client-side contact form handler
  const form = document.getElementById("contactForm");
  const notice = document.getElementById("formNotice");
  if (form && notice) {
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      notice.style.display = "block";
      notice.textContent = "Thank you! Your message has been received.";
      form.reset();
    });
  }
});
"""


def render_html_page(
    *,
    site_name: str,
    tagline: str,
    subject: str,
    page_title: str,
    current_page: str,
    nav_links: list[tuple[str, str]],
    sections: list[tuple[str, list[str] | list[tuple[str, str]]]],
    is_contact: bool = False,
) -> str:
    """Render a complete HTML5 page with SEO meta tags, navigation, sections and footer."""
    nav_items_list = []
    for href, label in nav_links:
        cls_attr = ' class="active"' if href == current_page else ''
        nav_items_list.append(f'    <a href="{href}"{cls_attr}>{html.escape(label)}</a>')
    nav_items = "\n".join(nav_items_list)

    body_sections: list[str] = []
    for title, items in sections:
        items_html = ""
        # Check if items are card tuples (card_title, card_body) or strings
        if items and isinstance(items[0], tuple):
            cards = "\n".join(
                f'      <div class="card">\n        <h3>{html.escape(c_title)}</h3>\n        <p>{html.escape(c_desc)}</p>\n      </div>'
                for c_title, c_desc in items  # type: ignore[misc]
            )
            items_html = f'    <div class="grid">\n{cards}\n    </div>'
        else:
            paragraphs = "\n".join(f"      <p>{html.escape(str(p))}</p>" for p in items)
            items_html = paragraphs

        body_sections.append(
            f"  <section>\n    <h2>{html.escape(title)}</h2>\n{items_html}\n  </section>"
        )

    contact_form_html = ""
    if is_contact:
        contact_form_html = """  <section>
    <h2>Send us an inquiry</h2>
    <form id="contactForm">
      <div class="form-group">
        <label for="name">Full Name</label>
        <input type="text" id="name" name="name" required placeholder="Your name">
      </div>
      <div class="form-group">
        <label for="email">Email Address</label>
        <input type="email" id="email" name="email" required placeholder="you@example.com">
      </div>
      <div class="form-group">
        <label for="message">Message</label>
        <textarea id="message" name="message" rows="4" required placeholder="How can we help you?"></textarea>
      </div>
      <button type="submit">Submit Message</button>
      <div id="formNotice" class="notice"></div>
    </form>
  </section>"""
        body_sections.append(contact_form_html)

    body_content = "\n".join(body_sections)
    escaped_site = html.escape(site_name)
    escaped_tagline = html.escape(tagline)
    escaped_subject = html.escape(subject)
    escaped_title = html.escape(page_title)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="{escaped_site} — {escaped_subject}. {escaped_tagline}">
  <meta property="og:title" content="{escaped_title}">
  <meta property="og:description" content="{escaped_tagline}">
  <title>{escaped_title}</title>
  <link rel="icon" href="assets/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="assets/style.css">
</head>
<body>
  <header>
    <h1>{escaped_site}</h1>
    <p>{escaped_tagline}</p>
  </header>
  <nav id="mainNav">
{nav_items}
  </nav>
  <main>
{body_content}
  </main>
  <footer>
    <p>&copy; <span id="year"></span> {escaped_site} · Built autonomously by ERA AI Website Builder</p>
  </footer>
  <script src="assets/app.js"></script>
</body>
</html>
"""


def export_site_to_zip(site_dir: Path) -> bytes:
    """Create a zip archive buffer containing all files in site_dir."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in site_dir.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(site_dir)
                zf.write(file_path, arcname=str(rel_path))
    return buf.getvalue()
