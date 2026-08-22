"""Offline knowledge/content pack for the MVEA website-builder goal (Phase 3A).

When no real LLM is configured (FREE LIMITATION), the deterministic brain
renders sites from these packs so the *entire agent loop* — planning, tool use,
file creation, verification, retry — still runs for real. When an LLM is
configured, the brain generates content from the model instead and this pack is
only the fallback.

Content is factual, educational material authored for the demo (welding
processes, safety, careers). It is rendered into a mobile-first static site.
"""

from __future__ import annotations

import html
from typing import Any

from era.agents.website_builder import generate_favicon_svg

# --------------------------------------------------------------------------
# Welding training site pack
# --------------------------------------------------------------------------

WELDING = {
    "subject": "Welding Training",
    "site_name": "ArcWeld Academy",
    "tagline": "Master the arc. Build your career in welding.",
    "slug": "welding_training_site",
    "pages": {
        "index.html": {
            "title": "ArcWeld Academy — Welding Training Institute",
            "nav": [("index.html", "Home"), ("safety.html", "Safety"), ("processes.html", "Processes"),
                    ("courses.html", "Courses"), ("career.html", "Career"), ("contact.html", "Contact")],
            "sections": [
                ("Welcome to ArcWeld Academy", [
                    ("ArcWeld Academy is a dedicated welding training institute helping students turn "
                    "sparks into skills. Our certified instructors teach hands-on welding from the "
                    "first bead to advanced pipe welding."),
                    ("Whether you are starting your career or upgrading your skills, our courses are "
                    "built around real workshop practice, safety discipline, and industry standards."),
                ]),
                ("Why train with us", [
                    "Industry-aligned curriculum covering SMAW, GTAW, GMAW and FCAW processes.",
                    "Real workshop hours — more than 70% of every course is hands-on practice.",
                    "Safety-first culture: PPE, ventilation, fire safety and electrical safety from day one.",
                    "Career support with placement guidance and certification preparation.",
                ]),
                ("Start your journey", [
                    ("Explore our courses, understand the processes, and contact us for admission "
                    "details. Your first weld starts here."),
                ]),
            ],
        },
        "safety.html": {
            "title": "Welding Safety — ArcWeld Academy",
            "nav": [("index.html", "Home"), ("safety.html", "Safety"), ("processes.html", "Processes"),
                    ("courses.html", "Courses"), ("career.html", "Career"), ("contact.html", "Contact")],
            "sections": [
                ("Personal Protective Equipment (PPE)", [
                    ("Always wear a welding helmet with the correct shade lens, flame-resistant "
                    "clothing, leather gloves and closed safety shoes. Never weld in synthetic "
                    "clothes that can melt onto skin."),
                ]),
                ("Ventilation and fumes", [
                    ("Welding fumes are hazardous. Work only in ventilated areas or with fume "
                    "extraction. When welding galvanised or coated metal, extra ventilation and "
                    "respiratory protection are mandatory."),
                ]),
                ("Fire safety", [
                    ("Keep a fire extinguisher nearby and clear the area of flammable materials. "
                    "Hot sparks can travel several metres — never weld near fuel, paint or "
                    "combustible dust."),
                ]),
                ("Electrical safety", [
                    ("Inspect cables, holders and earth clamps before every use. Never touch live "
                    "electrode parts with bare skin, and never work in wet conditions."),
                ]),
            ],
        },
        "processes.html": {
            "title": "Welding Processes — ArcWeld Academy",
            "nav": [("index.html", "Home"), ("safety.html", "Safety"), ("processes.html", "Processes"),
                    ("courses.html", "Courses"), ("career.html", "Career"), ("contact.html", "Contact")],
            "sections": [
                ("SMAW — Shielded Metal Arc Welding (Stick)", [
                    ("The most widely used manual process. A flux-coated electrode creates both the "
                    "arc and the shielding gas. Ideal for construction, repair and outdoor work."),
                ]),
                ("GTAW — Gas Tungsten Arc Welding (TIG)", [
                    ("Uses a non-consumable tungsten electrode with a separate filler rod and inert "
                    "gas shielding. Produces the cleanest, most precise welds — the standard for "
                    "stainless steel, aluminium and thin sheet."),
                ]),
                ("GMAW — Gas Metal Arc Welding (MIG/MAG)", [
                    ("A continuously fed wire electrode with gas shielding. Fast, easier to learn, "
                    "and dominant in fabrication and automotive manufacturing."),
                ]),
                ("FCAW — Flux-Cored Arc Welding", [
                    ("A wire-fed process with a flux core that generates its own shielding. High "
                    "deposition rates make it popular for heavy fabrication and shipbuilding."),
                ]),
            ],
        },
        "courses.html": {
            "title": "Welding Courses — ArcWeld Academy",
            "nav": [("index.html", "Home"), ("safety.html", "Safety"), ("processes.html", "Processes"),
                    ("courses.html", "Courses"), ("career.html", "Career"), ("contact.html", "Contact")],
            "sections": [
                ("Beginner Welder (4 weeks)", [
                    ("Safety and PPE, metal preparation, oxy-fuel cutting basics, SMAW bead "
                    "practice in flat position, and an introduction to workshop tools."),
                ]),
                ("Intermediate Welder (6 weeks)", [
                    ("SMAW in all positions, GMAW (MIG) fundamentals, blueprint reading basics, "
                    "weld inspection and defect identification."),
                ]),
                ("Advanced TIG Specialist (6 weeks)", [
                    ("GTAW on carbon steel, stainless steel and aluminium, thin-sheet technique, "
                    "pipe root welding preparation, and welder qualification test practice."),
                ]),
                ("Pipe & Structural Welding (8 weeks)", [
                    ("6G pipe welding, FCAW heavy plate, fit-up and jig work, followed by an "
                    "industry certification mock test."),
                ]),
            ],
        },
        "career.html": {
            "title": "Welding Careers — ArcWeld Academy",
            "nav": [("index.html", "Home"), ("safety.html", "Safety"), ("processes.html", "Processes"),
                    ("courses.html", "Courses"), ("career.html", "Career"), ("contact.html", "Contact")],
            "sections": [
                ("Where welders work", [
                    ("Construction and infrastructure, shipbuilding and offshore, oil, gas and "
                    "pipelines, automotive and aerospace fabrication, and repair workshops."),
                ]),
                ("Certification", [
                    ("Industry-recognised welder qualification tests (such as those aligned with "
                    "AWS D1.1 structural codes) open doors to better projects and higher pay. Our "
                    "advanced courses include mock qualification tests."),
                ]),
                ("Career path", [
                    ("Welder helper → certified welder → specialist (TIG/pipe) → supervisor → "
                    "inspector or trainer. Skilled welders are in steady demand across India and "
                    "the world."),
                ]),
            ],
        },
        "contact.html": {
            "title": "Contact — ArcWeld Academy",
            "nav": [("index.html", "Home"), ("safety.html", "Safety"), ("processes.html", "Processes"),
                    ("courses.html", "Courses"), ("career.html", "Career"), ("contact.html", "Contact")],
            "sections": [
                ("Get in touch", [
                    ("Visit our workshop or send an enquiry to book a campus tour and a free "
                    "counselling session."),
                    "Workshop: 12 Industrial Estate Road, Pune, Maharashtra (demo address).",
                    "Phone: +91-98XXXXXXXX (demo number). Email: admissions@arcweld.example.",
                ]),
            ],
        },
    },
    "readme": (
        "# ArcWeld Academy — Welding Training Website\n\n"
        "Static, mobile-first training site generated by the ERA agent.\n\n"
        "Pages:\n- index.html — home\n- safety.html — PPE, fumes, fire, electrical safety\n"
        "- processes.html — SMAW, GTAW, GMAW, FCAW\n- courses.html — beginner to pipe welding\n"
        "- career.html — industries, certification, career path\n- contact.html — contact info\n\n"
        "Assets: assets/style.css, assets/app.js\n"
    ),
}

# --------------------------------------------------------------------------
# Generic fallback pack (any subject without dedicated content)
# --------------------------------------------------------------------------


def generic_pack(subject: str) -> dict[str, Any]:
    slug = "".join(c if c.isalnum() else "_" for c in subject.lower()).strip("_") or "site"
    nav = [("index.html", "Home"), ("about.html", "About"), ("contact.html", "Contact")]
    return {
        "subject": subject,
        "site_name": subject.title(),
        "tagline": f"Learn about {subject.lower()} — generated by the ERA agent.",
        "slug": f"{slug}_site",
        "pages": {
            "index.html": {
                "title": f"{subject.title()} — Home",
                "nav": nav,
                "sections": [
                    (f"Welcome to {subject.title()}", [
                        (f"This site is a structured introduction to {subject.lower()}, generated "
                        "by the ERA autonomous agent as a demonstration of planning, tool use and "
                        "verification."),
                    ]),
                    ("What you will find", [
                        "Overview content, an about page with key information, and contact details.",
                    ]),
                ],
            },
            "about.html": {
                "title": f"About {subject.title()}",
                "nav": nav,
                "sections": [
                    ("About", [
                        (f"{subject.title()} is a broad and practical topic. This page summarises "
                        "the fundamentals and where to learn more."),
                    ]),
                    ("Getting started", [
                        ("Begin with the basics, practice regularly, and verify your progress with "
                        "simple checks — exactly the loop this agent used to build this site."),
                    ]),
                ],
            },
            "contact.html": {
                "title": f"Contact — {subject.title()}",
                "nav": nav,
                "sections": [
                    ("Contact", [
                        "Email: info@example.in (demo). Phone: +91-98XXXXXXXX (demo).",
                    ]),
                ],
            },
        },
        "readme": f"# {subject.title()} — generated site\n\nBuilt by the ERA agent (offline pack).\n",
    }


def resolve_pack(subject: str) -> dict[str, Any]:
    """Return the best content pack for ``subject`` (welding pack or generic)."""
    lowered = subject.lower()
    if "weld" in lowered:
        return WELDING
    return generic_pack(subject)


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

_CSS = """/* ArcWeld style — mobile-first */
:root { --bg:#0f172a; --card:#1e293b; --accent:#f59e0b; --text:#e2e8f0; }
* { box-sizing: border-box; }
body { margin:0; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
       background:var(--bg); color:var(--text); line-height:1.6; }
header { background:var(--card); padding:1rem; border-bottom:2px solid var(--accent); }
header h1 { margin:0 0 .25rem; font-size:1.4rem; color:var(--accent); }
header p { margin:0; opacity:.8; font-size:.9rem; }
nav { display:flex; flex-wrap:wrap; gap:.4rem; padding:.75rem 1rem; background:#0b1120; }
nav a { color:var(--text); text-decoration:none; padding:.35rem .7rem; border-radius:6px;
        background:#1e293b; font-size:.9rem; }
nav a:hover, nav a.active { background:var(--accent); color:#0f172a; }
main { padding:1rem; max-width:64rem; margin:0 auto; }
section { background:var(--card); border-radius:10px; padding:1rem 1.25rem; margin-bottom:1rem; }
h2 { color:var(--accent); margin:.25rem 0 .5rem; font-size:1.15rem; }
ul { padding-left:1.2rem; margin:.4rem 0; }
li { margin-bottom:.4rem; }
footer { text-align:center; padding:1rem; opacity:.7; font-size:.85rem; }
.hero { background:linear-gradient(135deg,#1e293b,#334155); text-align:center; padding:2rem 1rem; }
.hero strong { color:var(--accent); }
"""

_JS = """// ArcWeld Academy — tiny client-side script
document.addEventListener('DOMContentLoaded', function () {
  // Highlight the active nav link
  var current = (location.pathname.split('/').pop() || 'index.html');
  document.querySelectorAll('nav a').forEach(function (a) {
    if (a.getAttribute('href') === current) a.classList.add('active');
  });
  // Footer year
  var year = document.getElementById('year');
  if (year) year.textContent = String(new Date().getFullYear());
  // Mobile nav toggle
  var btn = document.getElementById('navToggle');
  if (btn) btn.addEventListener('click', function () {
    var nav = document.getElementById('mainNav');
    nav.style.display = nav.style.display === 'none' ? 'flex' : 'none';
  });
});
"""


def render_page(pack: dict[str, Any], page_key: str) -> str:
    """Render one HTML page from the pack."""
    page = pack["pages"][page_key]
    nav_html = "\n".join(
        f'      <a href="{href}">{html.escape(label)}</a>' for href, label in page["nav"]
    )
    sections = []
    for heading, paragraphs in page["sections"]:
        items = "\n".join(f"        <li>{html.escape(p)}</li>" for p in paragraphs)
        sections.append(f"    <section>\n      <h2>{html.escape(heading)}</h2>\n"
                        f"      <ul>{items}\n      </ul>\n    </section>")
    body = "\n".join(sections)
    site_name = html.escape(pack["site_name"])
    title = html.escape(page["title"])
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="{site_name} — {html.escape(pack['subject'])}">
  <title>{title}</title>
  <link rel="stylesheet" href="assets/style.css">
</head>
<body>
  <header>
    <h1>{site_name}</h1>
    <p>{html.escape(pack['tagline'])}</p>
  </header>
  <nav id="mainNav">
{nav_html}
  </nav>
  <main>
{body}
  </main>
  <footer>
    <p>&copy; <span id="year"></span> {site_name} · Built by the ERA autonomous agent</p>
  </footer>
  <script src="assets/app.js"></script>
</body>
</html>
"""


def render_site(pack: dict[str, Any]) -> dict[str, str]:
    """Render the whole site: path -> content (relative to the site root)."""
    site_dir = pack["slug"]
    out: dict[str, str] = {
        f"{site_dir}/README.md": pack["readme"],
        f"{site_dir}/assets/style.css": _CSS,
        f"{site_dir}/assets/app.js": _JS,
    }
    for page_key in pack["pages"]:
        out[f"{site_dir}/{page_key}"] = render_page(pack, page_key)
    return out


def content_for(pack: dict[str, Any], content_key: str) -> str:
    """Resolve a ``content_from`` key to rendered content.

    Keys: ``<pack>:index.html`` (rendered page), ``<pack>:readme``,
    ``<pack>:style.css``, ``<pack>:app.js``, ``<pack>:favicon.svg``.
    """
    _, _, key = content_key.partition(":")
    if key in pack["pages"]:
        return render_page(pack, key)
    if key == "readme":
        return pack["readme"]
    if key in ("style.css", "css"):
        return _CSS
    if key in ("app.js", "js"):
        return _JS
    if key in ("favicon.svg", "favicon"):
        return generate_favicon_svg(pack.get("site_name", "ERA"))
    raise KeyError(f"unknown content key: {content_key!r}")
