import base64, pathlib, re, sys

src = pathlib.Path("panel_brief.src.html").read_text()
figdir = pathlib.Path("/home/a5hx/Zero-Trust-Enabled-SDN-Architecture/ppt/figures")

missing = []
def repl(m):
    name = m.group(1)
    p = figdir / name
    if not p.exists():
        missing.append(name)
        return "<!-- MISSING %s -->" % name
    b64 = base64.b64encode(p.read_bytes()).decode()
    return '<figure><img src="data:image/png;base64,%s" alt="%s"></figure>' % (b64, name)

out = re.sub(r"\{\{FIG:([^}]+)\}\}", repl, src)
leftover = re.findall(r"\{\{[^}]*\}\}", out)
pathlib.Path("panel_brief.html").write_text(out)
print("missing figures:", missing or "none")
print("leftover placeholders:", leftover or "none")
print("html bytes:", len(out))

# Build:
#   cp ppt/panel_brief.src.html ppt/build_panel_brief.py ~/pdfbuild/ && cd ~/pdfbuild
#   python3 build_panel_brief.py            # inlines ppt/figures/*.png as data: URIs
#   chromium --headless --disable-gpu --no-sandbox --no-pdf-header-footer \
#            --virtual-time-budget=20000 --print-to-pdf=panel_brief.pdf panel_brief.html
# NOTE: chromium is a snap here; it CANNOT write outside $HOME. Build under ~/pdfbuild,
# then copy the PDF back into the repo.
