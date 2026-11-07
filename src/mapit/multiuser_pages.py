"""Pure HTML pages for the invitation-only multiuser identity Lambda.

See docs/multiuser-production.md ("Accept" and "Privacy and consent"). Every
interpolated value is escaped with ``html.escape``. Pages contain no scripts,
no external assets and only inline CSS, matching the fixed CSP.
"""

from __future__ import annotations

from html import escape

from .multiuser_common import CLAUDE_CODE_CALLBACK_PORT, CONSENT_VERSION

GENERIC_INVITATION_ERROR = "Enlace no válido o caducado. Pide uno nuevo al administrador."
NOT_FOUND_MESSAGE = "Página no encontrada."
UNAVAILABLE_MESSAGE = "Servicio no disponible temporalmente. Inténtalo más tarde."

_STYLE = (
    "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:40rem;"
    "margin:2rem auto;padding:0 1rem;line-height:1.5;color:#1d1d1f;background:#fafafa}"
    "h1{font-size:1.5rem}h2{font-size:1.15rem;margin-top:1.75rem}"
    "code,pre{font-family:ui-monospace,Consolas,monospace;background:#eee;border-radius:4px}"
    "code{padding:.1rem .3rem;word-break:break-all}"
    "pre{padding:.75rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all}"
    ".box{background:#fff;border:1px solid #ddd;border-radius:8px;padding:1rem 1.25rem}"
    "button{font-size:1rem;padding:.6rem 1.2rem;border:0;border-radius:6px;"
    "background:#c00;color:#fff;cursor:pointer}"
    "label{display:block;margin:1rem 0}small{color:#555}"
)


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<meta name=\"robots\" content=\"noindex,nofollow\">"
        f"<title>{escape(title)}</title><style>{_STYLE}</style></head>"
        f"<body>{body}<p><small>Honda MAPIT MCP · proyecto personal, no afiliado a Honda."
        " <a href=\"/privacidad\">Privacidad</a></small></p></body></html>"
    )


def render_consent_form(email: str, token: str) -> str:
    """Consent page. It does not reveal whether the invitation exists."""
    body = (
        "<h1>Invitación a Honda MAPIT MCP</h1>"
        "<div class=\"box\"><p>Este servicio permite que tu asistente de IA (Claude o Codex) "
        "consulte, solo en modo lectura, los datos de tu moto en MAPIT: estado del vehículo, "
        "rutas y distancias. Entrarás con tu email y contraseña de MAPIT.</p>"
        "<p><strong>Resumen de privacidad:</strong> guardamos tu email, un identificador "
        "opaco y tu sesión de MAPIT cifrada. Tu contraseña no se guarda en nuestro código "
        "ni en nuestra base de datos. Los datos de MAPIT se leen cuando preguntas y no se "
        "almacenan. Puedes borrar tus datos cuando quieras. "
        "<a href=\"/privacidad\">Política de privacidad completa</a>.</p></div>"
        "<form method=\"post\" action=\"/invitacion\">"
        f"<input type=\"hidden\" name=\"email\" value=\"{escape(email, quote=True)}\">"
        f"<input type=\"hidden\" name=\"token\" value=\"{escape(token, quote=True)}\">"
        f"<p>Invitación para: <strong>{escape(email)}</strong></p>"
        "<label><input type=\"checkbox\" name=\"consent\" value=\"on\" required> "
        "He leído la política de privacidad y doy mi consentimiento para el tratamiento "
        "descrito.</label>"
        "<button type=\"submit\">Aceptar invitación</button></form>"
    )
    return _page("Invitación", body)


def render_success(
    resource_url: str,
    claude_client_id: str,
    codex_client_id: str,
    codex_callback_port: int,
) -> str:
    url = escape(resource_url)
    claude_id = escape(claude_client_id)
    codex_id = escape(codex_client_id)
    port = escape(str(codex_callback_port))
    # Codex flags verified against https://learn.chatgpt.com/docs/extend/mcp?surface=cli
    # (2026-10-23): `codex mcp add NAME --url URL --oauth-client-id ID`,
    # `[mcp_servers.NAME.oauth] callback_port`, `codex mcp login NAME --scopes`.
    body = (
        "<h1>Invitación aceptada</h1>"
        "<p>Ya puedes conectar tu asistente. Dirección del servidor MCP:</p>"
        f"<pre>{url}</pre>"
        "<h2>Claude (claude.ai o Claude Desktop)</h2><ol>"
        "<li>Abre <strong>Configuración → Conectores → Añadir conector personalizado</strong> "
        "(<em>Settings → Connectors → Add custom connector</em>).</li>"
        f"<li>Nombre: <code>Honda MAPIT</code>. URL: <code>{url}</code></li>"
        "<li>En <strong>Configuración avanzada</strong> (<em>Advanced settings</em>), "
        f"ID de cliente OAuth: <code>{claude_id}</code>. Deja el secreto de cliente vacío.</li>"
        "<li>Pulsa <strong>Conectar</strong>.</li></ol>"
        "<h2>Claude Code</h2><ol>"
        "<li>Ejecuta:<pre>claude mcp add --transport http --scope user "
        f"--client-id {claude_id} --callback-port {CLAUDE_CODE_CALLBACK_PORT} honda-mapit {url}</pre></li>"
        "<li>Abre Claude Code, escribe <code>/mcp</code>, elige <code>honda-mapit</code> y "
        "pulsa <strong>Authenticate</strong>.</li></ol>"
        "<h2>Codex</h2><ol>"
        f"<li>Ejecuta:<pre>codex mcp add honda-mapit --url {url} --oauth-client-id {codex_id}</pre></li>"
        "<li>Añade en <code>~/.codex/config.toml</code> el puerto de retorno fijo:"
        f"<pre>[mcp_servers.honda-mapit.oauth]\ncallback_port = {port}</pre></li>"
        f"<li>Inicia sesión:<pre>codex mcp login honda-mapit --scopes openid,{url}/use</pre></li></ol>"
        "<h2>Iniciar sesión</h2>"
        "<p>Inicia sesión con tu email y contraseña de MAPIT. La primera vez puede tardar "
        "unos segundos mientras comprobamos tu cuenta con MAPIT.</p>"
        "<p><small>Para borrar tus datos en cualquier momento, pide a tu asistente que use "
        "la herramienta <code>borrar_mis_datos</code>.</small></p>"
    )
    return _page("Invitación aceptada", body)


def render_message(message: str, title: str = "Honda MAPIT MCP") -> str:
    return _page(title, f"<h1>{escape(title)}</h1><p>{escape(message)}</p>")


def render_invitation_error() -> str:
    return render_message(GENERIC_INVITATION_ERROR, "Enlace no válido")


def render_not_found() -> str:
    return render_message(NOT_FOUND_MESSAGE, "No encontrado")


def render_unavailable() -> str:
    return render_message(UNAVAILABLE_MESSAGE, "No disponible")


def render_privacy(contact_email: str) -> str:
    contact = escape(contact_email)
    body = (
        "<h1>Política de privacidad</h1>"
        f"<p><small>Versión {escape(CONSENT_VERSION)}</small></p>"
        "<h2>Responsable</h2>"
        "<p>El administrador de este proyecto personal, que te ha invitado. Contacto: "
        f"<a href=\"mailto:{contact}\">{contact}</a>.</p>"
        "<h2>Para qué</h2>"
        "<p>Responder a tus propias preguntas sobre tu moto a través del asistente de IA "
        "que elijas (por ejemplo Claude o Codex), usando tu cuenta de MAPIT en modo solo "
        "lectura.</p>"
        "<h2>Qué datos tratamos</h2><ul>"
        "<li>Tu email y un identificador opaco aleatorio.</li>"
        "<li>Tu sesión de MAPIT (un token de renovación), guardada cifrada. No guardamos tu "
        "contraseña de MAPIT en nuestro código ni en nuestra base de datos; el servicio de "
        "inicio de sesión de Amazon Cognito conserva su propio resumen cifrado (hash) para "
        "que puedas volver a entrar.</li>"
        "<li>Fechas de consentimiento, de último inicio de sesión e intentos fallidos.</li>"
        "</ul>"
        "<p>Los datos de MAPIT (estado, rutas, distancias) se leen cuando preguntas y no los "
        "almacenamos. El asistente de IA que uses procesa las respuestas según sus propias "
        "condiciones.</p>"
        "<h2>Base legal</h2><p>Tu consentimiento, que puedes retirar en cualquier momento.</p>"
        "<h2>Conservación</h2>"
        "<p>Hasta que borres tus datos o tras 12 meses sin uso.</p>"
        "<h2>Tus derechos</h2>"
        "<p>Puedes borrar tus datos al instante pidiendo a tu asistente que use la "
        "herramienta <code>borrar_mis_datos</code>, o escribiendo al contacto indicado. "
        "También puedes pedir acceso o rectificación.</p>"
        "<h2>Encargados y ubicación</h2>"
        "<p>Amazon Web Services, región UE (Irlanda, eu-west-1).</p>"
        "<h2>Cesión</h2><p>No vendemos ni compartimos tus datos con terceros.</p>"
        "<h2>Aviso</h2><p>Este proyecto no está afiliado a Honda ni a MAPIT.</p>"
    )
    return _page("Política de privacidad", body)


__all__ = [
    "GENERIC_INVITATION_ERROR", "NOT_FOUND_MESSAGE", "UNAVAILABLE_MESSAGE",
    "render_consent_form", "render_success", "render_message", "render_invitation_error",
    "render_not_found", "render_unavailable", "render_privacy",
]
