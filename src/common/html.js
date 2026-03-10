const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="72" height="72" viewBox="0 0 72 72">
  <rect width="72" height="72" rx="16" fill="#0f172a"/>
  <path d="M24 15L11 24v24l13 9" fill="none" stroke="#e2e8f0" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M48 15l13 9v24l-13 9" fill="none" stroke="#e2e8f0" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M39 9L25 36h8l-3 27 16-31h-9z" fill="#22d3ee"/>
</svg>`;

const FAVICON_DATA_URL = `data:image/svg+xml,${encodeURIComponent(FAVICON_SVG)}`;

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function capitalize(s) {
  const v = String(s || "");
  if (!v) return v;
  return v.charAt(0).toUpperCase() + v.slice(1);
}

function htmlPage(title, bodyHtml) {
  const safeTitle = escapeHtml(title || "");
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${safeTitle}</title>
    <link rel="icon" href="${FAVICON_DATA_URL}" />
    <style>
      body { font-family: system-ui, sans-serif; margin: 24px; color: #111827; }
      h1 { margin: 0 0 12px 0; font-size: 20px; }
      p { margin: 0 0 10px 0; line-height: 1.45; }
    </style>
  </head>
  <body>
    ${safeTitle ? `<h1>${safeTitle}</h1>` : ""}
    ${bodyHtml || ""}
  </body>
</html>`;
}

export { FAVICON_DATA_URL, escapeHtml, capitalize, htmlPage };
