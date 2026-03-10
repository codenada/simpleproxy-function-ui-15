import pageTemplate from "./ui/templates/page.html";
import onboardingHeaderTemplate from "./ui/templates/onboarding_header.html";
import adminLoginOptionsTemplate from "./ui/templates/admin_login_options.html";
import adminPageTemplate from "./ui/templates/admin_page.html";
import secretFieldTemplate from "./ui/templates/secret_field.html";
import initAdminLoginScriptTemplate from "./ui/templates/init_admin_login_script.html";
import secretFieldScriptTemplate from "./ui/templates/secret_field_script.html";
import adminPageScriptTemplate from "./ui/templates/admin_page_script.html";
import sandboxTemplatesTemplate from "./ui/templates/sandbox_templates.html";
import { FAVICON_DATA_URL, escapeHtml, capitalize } from "../common/html.js";

const templates = {
  page: pageTemplate,
  onboarding_header: onboardingHeaderTemplate,
  admin_login_options: adminLoginOptionsTemplate,
  admin_page: adminPageTemplate,
  init_admin_login_script: initAdminLoginScriptTemplate,
  secret_field: secretFieldTemplate,
  secret_field_script: secretFieldScriptTemplate,
  admin_page_script: adminPageScriptTemplate,
  sandbox_templates: sandboxTemplatesTemplate,
};

function renderTemplate(name, vars = {}) {
  const src = templates[name] || "";
  return src.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_, key) => (key in vars ? String(vars[key]) : ""));
}

export { FAVICON_DATA_URL, escapeHtml, capitalize };

export function htmlPage(title, bodyHtml) {
  const safeTitle = escapeHtml(title || "");
  return renderTemplate("page", {
    title: safeTitle,
    favicon_data_url: FAVICON_DATA_URL,
    heading_text: safeTitle,
    heading_style: safeTitle ? "" : "display:none;",
    body_html: bodyHtml || "",
  });
}

export function renderOnboardingHeader(proxyName = "") {
  const name = String(proxyName || "").trim();
  return renderTemplate("onboarding_header", {
    favicon_data_url: FAVICON_DATA_URL,
    proxy_name: escapeHtml(name),
    proxy_name_style: name ? "" : "display:none;",
  });
}

export function renderAdminLoginOptions(docsUrl) {
  return renderTemplate("admin_login_options", {
    docs_url: escapeHtml(docsUrl || ""),
  });
}

export function renderInitAdminLoginScript(adminRoot) {
  return renderTemplate("init_admin_login_script", {
    admin_root: String(adminRoot || ""),
  });
}

export function renderSecretField(label, value, id, note = "", actionsEnabled = true) {
  const disabledAttr = actionsEnabled ? "" : " disabled";
  const buttonStyle = actionsEnabled
    ? "padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;background:#fff;cursor:pointer;"
    : "padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;background:#f3f4f6;color:#9ca3af;cursor:not-allowed;opacity:0.85;";
  const noteBlock = note ? `<div style=\"margin-top:6px;color:#6b7280;font-size:12px;\">${String(note)}</div>` : "";
  return renderTemplate("secret_field", {
    label: escapeHtml(label),
    value: escapeHtml(value),
    id: escapeHtml(id),
    button_style: buttonStyle,
    disabled_attr: disabledAttr,
    note_block: noteBlock,
  });
}

export function renderSecretFieldScript() {
  return templates.secret_field_script || "";
}

export function renderAdminPage(adminRoot = "/admin") {
  const adminPageScriptHtml = renderTemplate("admin_page_script", {
    admin_root: String(adminRoot || "/admin"),
    sandbox_templates_js: templates.sandbox_templates || "",
  });
  const bodyHtml = renderTemplate("admin_page", {
    favicon_data_url: FAVICON_DATA_URL,
    admin_root: String(adminRoot || "/admin"),
    admin_page_script_html: adminPageScriptHtml,
  });
  return new Response(
    htmlPage("", bodyHtml),
    { headers: { "content-type": "text/html; charset=utf-8" } }
  );
}
