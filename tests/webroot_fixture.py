"""Builds a webroot with HARMLESS shell-like markers plus clean pages.

Nothing here works as malware: dangerous-looking constructs sit inside comments or operate on constant strings
that decode to the word IISGUARD. Secrets are assembled from fragments so no full key literal exists in the repo
(and GitHub secret scanning stays quiet). Run `python tests/webroot_fixture.py OUT_DIR` to materialize it.
"""

from __future__ import annotations

import sys
from pathlib import Path

PNG = b"\x89PNG\r\n\x1a\n"
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(range(256)) * 4

# relative path -> content. These MUST be flagged by `hunt`.
PLANTED: dict[str, bytes] = {
    "wp-content/uploads/2026/11/img-cache.php": b'<?php /* IISGUARD-TEST-MARKER */ eval(base64_decode("SUlTR1VBUkQ=")); ?>\n',
    "app/UpdateChecker.aspx": b'<%@ Page Language="C#" %>\n<%-- IISGUARD-TEST-MARKER Assembly.Load(Convert.FromBase64String("SUlTR1VBUkQ=")) --%>\n',
    "images/banner.png": PNG + b"<?php /* IISGUARD-TEST-MARKER */ ?>\n",
    "site1/.user.ini": b"auto_prepend_file = /var/www/html/wp-content/uploads/IISGUARD-TEST-MARKER.php\n",
    "images/logo.png.aspx": b"<%-- IISGUARD-TEST-MARKER --%>\n",
    "exchange/owa/auth/IISGUARDTEST.aspx": b'<%@ Page Language="C#" %>\n',
    "jsp/cmd.jsp": b'<%-- IISGUARD-TEST-MARKER Runtime.getRuntime().exec(request.getParameter("c")) --%>\n',
    "lib/cache.php": b"<?php // IISGUARD-TEST-MARKER\n// $_POST['IISGUARD']('constant');\n?>\n",
    "uploads/web.config": (
        b"<configuration><system.webServer><handlers>"
        b'<add name="IISGUARDTEST" path="*.png" verb="*" modules="ManagedPipelineHandler" />'
        b"</handlers></system.webServer></configuration>\n"
    ),  # fmt: skip
    "uploads/.htaccess": b"AddHandler application/x-httpd-php .jpg\n",
}
# Only flagged when --since is used (recent .aspx under SharePoint _layouts).
RECENT_ONLY = {"sp/_layouts/15/IISGUARDtest.aspx": b'<%@ Page Language="C#" %>\n'}

B64 = "A" * 700  # a long embedded data URI is legitimate in templates
CLEAN: dict[str, bytes] = {
    "index.php": b"<?php\ndefine('WP_USE_THEMES', true);\nrequire __DIR__ . '/wp-blog-header.php';\n",
    "wp-content/uploads/index.php": b"<?php\n// Silence is golden.\n",
    "wp-content/plugins/contact/form.php": (
        b"<?php\nif (isset($_POST['email'])) {\n  $e = sanitize_text_field($_POST['email']);\n"
        b"  $t = base64_decode($token);\n  wp_verify_nonce($_POST['n'], 'contact');\n}\n"
    ),
    "Default.aspx": b'<%@ Page Language="C#" CodeBehind="Default.aspx.cs" Inherits="Site.Default" %>\n<html><body>\n'
    b'<%= Request.QueryString["id"] %></body></html>\n',  # fmt: skip
    "Admin/Tools.aspx": b'<%@ Page Language="C#" %>\n<script runat="server">void Page_Load(object s, EventArgs e){ Label1.Text = DateTime.Now.ToString(); }</script>\n',
    "templates/mail.php": b"<?php\n$logo = 'data:image/png;base64," + B64.encode() + b"';\n",
    "images/photo.jpg": JPEG,
    "images/icon.png": PNG + bytes(range(256)),
    "docs/readme.txt": b"Notes: avoid eval(base64_decode(...)) patterns in your own code.\n",
    "web.config": b'<configuration><system.web><compilation debug="false"/><machineKey validationKey="AutoGenerate,IsolateApps" decryptionKey="AutoGenerate,IsolateApps"/></system.web></configuration>\n',
    ".htaccess": b"RewriteEngine On\nRewriteRule ^index\\.php$ - [L]\n",
    "site2/.user.ini": b"upload_max_filesize = 20M\n",
    "wp-content/uploads/2026/photo.png": PNG + bytes(range(256)),
    "assets/app.min.js": b"!function(){var a=1;console.log(a)}();\n",
}

KEY_A = "AB" * 32
KEY_B = "CD" * 32


def secrets_files() -> dict[str, bytes]:
    anth = "sk-ant-" + "api03-" + "A" * 40
    oai = "sk-" + "proj-" + "B" * 40
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    stripe = "sk_" + "live_" + "C" * 24
    return {
        "secrets/.env": f"ANTHROPIC_API_KEY={anth}\nOPENAI_API_KEY={oai}\nAWS_ACCESS_KEY_ID={aws}\nSTRIPE_SECRET={stripe}\n".encode(),
        "secrets/appsettings.Production.json": b'{"ConnectionStrings":{"Default":"Server=db;User Id=app;Password=Sup3rS3cretPw!;"}}\n',
        "secrets/wp-config.php.bak": b"<?php\ndefine('DB_PASSWORD', 'hunter2hunter2');\n",
        "secrets/js/app.js": f"const k='{stripe}';\n".encode(),
        "secrets/src/config.php": f"<?php $k='{oai}';\n".encode(),
        "secrets/.git/config": b"[core]\n",
        "secrets/.env.example": b"ANTHROPIC_API_KEY=your-key-here\n",
    }


def webconfig_files() -> dict[str, bytes]:
    def wc(vk: str, dk: str) -> bytes:
        return f'<configuration><system.web><machineKey validationKey="{vk}" decryptionKey="{dk}" validation="HMACSHA256" decryption="AES"/></system.web></configuration>\n'.encode()

    return {
        "wc/siteA/web.config": wc(KEY_A, KEY_B),
        "wc/siteB/web.config": wc(KEY_A, KEY_B),  # shares siteA's keys
        "wc/siteC/web.config": wc("EF" * 32, "01" * 16),  # unique, still hard-coded
        "wc/siteD/web.config": b'<configuration><system.web><pages enableViewStateMac="false"/><compilation debug="true"/><customErrors mode="Off"/></system.web></configuration>\n',
        "wc/siteE/web.config": b'<configuration><system.web><machineKey validationKey="AutoGenerate,IsolateApps" decryptionKey="AutoGenerate,IsolateApps"/></system.web><system.webServer><security><requestFiltering><requestLimits maxAllowedContentLength="10485760"/></requestFiltering></security></system.webServer></configuration>\n',
    }


def write(root: Path, files: dict[str, bytes]) -> None:
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def build(root: Path, include_recent_only: bool = False) -> None:
    write(root, PLANTED)
    write(root, CLEAN)
    if include_recent_only:
        write(root, RECENT_ONLY)


if __name__ == "__main__":
    out = Path(sys.argv[1])
    build(out, True)
    write(out, secrets_files())
    write(out, webconfig_files())
    print(f"fixture written to {out}")
