"""Block script execution in upload folders (IIS web.config / Apache .htaccess; nginx snippet)."""

from __future__ import annotations

from pathlib import Path

from iisguard.fix.base import Change, FixPlan
from iisguard.fix.xmledit import validate

SCRIPT_EXTS = [".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht", ".phar", ".asp", ".aspx", ".ashx", ".asmx",
               ".ascx", ".cshtml", ".jsp", ".jspx", ".cgi", ".pl", ".py"]  # fmt: skip


def iis_config(handlers: bool) -> str:
    exts = "\n".join(f'          <add fileExtension="{e}" allowed="false" />' for e in SCRIPT_EXTS)
    hnd = '    <handlers accessPolicy="Read" />\n' if handlers else ""
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n<configuration>\n  <system.webServer>\n'
        f'{hnd}    <security>\n      <requestFiltering>\n        <fileExtensions allowUnlisted="true">\n{exts}\n'
        "        </fileExtensions>\n      </requestFiltering>\n    </security>\n  </system.webServer>\n</configuration>\n"
    )


def htaccess() -> str:
    pat = "|".join(e[1:] for e in SCRIPT_EXTS)
    return (
        "# added by iisguard: no script execution in this folder\n"
        f'<FilesMatch "\\.({pat})$">\n  Require all denied\n</FilesMatch>\n'
        "RemoveHandler .php .phtml .pht .phar\n"
    )


def nginx_snippet(location: str) -> str:
    pat = "|".join(e[1:] for e in SCRIPT_EXTS)
    return f"location ~* ^{location.rstrip('/')}/.*\\.({pat})$ {{\n    deny all;\n    return 404;\n}}"


def plan(dirs: list[str], server: str = "iis", handlers: bool = False) -> FixPlan:
    fp = FixPlan("uploads")
    for d in dirs:
        base = Path(d)
        if not base.is_dir():
            fp.notes.append(f"skipped {d}: not a directory")
            continue
        target = base / ("web.config" if server == "iis" else ".htaccess")
        if target.exists():
            fp.notes.append(
                f"skipped {target}: already exists. Merge the rules by hand (see snippets); iisguard never overwrites it."
            )
            continue
        text = iis_config(handlers) if server == "iis" else htaccess()
        if server == "iis":
            validate(text)
        fp.changes.append(Change(target, text, f"deny script execution in {base.name}/", None))
    fp.snippets = {"nginx": nginx_snippet("/wp-content/uploads"), "apache": htaccess(), "iis": iis_config(handlers)}
    fp.notes.append(
        "Verify uploads still display (images, PDFs). Executable-extension requests now return 404.8 / 403."
    )
    if handlers:
        fp.notes.append(
            "--handlers needs the 'Handlers' feature delegated as Read/Write in IIS; otherwise the folder returns HTTP 500.19."
        )
    return fp
