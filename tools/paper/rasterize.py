"""Rasterise the paper figures to PNG for the Word file.

The inline SVGs are written against the page's CSS custom properties and figure
classes, which only exist in the parent document. This resolves both against the
LIGHT palette (Word has no theme to follow) and produces standalone SVGs that a
rasteriser can render on its own.
"""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_REPO = _os.path.dirname(_os.path.dirname(_HERE))
import re
import cairosvg

S = _HERE          # figures + template live beside these scripts

# Light-mode values, copied from the paper's bare :root block.
TOKENS = {
    'ground': '#fbfbfc', 'surface-2': '#f2f4f7', 'surface-3': '#e9edf2',
    'ink': '#12151a', 'ink-2': '#4a515c', 'ink-muted': '#767e8b',
    'rule': '#dfe3e9', 'rule-strong': '#c3cad4',
    'accent': '#1f5fa8', 'accent-soft': '#e6eef8',
    's1': '#2a78d6', 's2': '#eb6834', 's3': '#1baf7a', 's4': '#eda100', 's5': '#e87ba4',
    'cell-0': '#f4f6f9', 'cell-lo': '#cfe0f5', 'cell-md': '#8fbaea',
    'cell-hi': '#1f5fa8', 'cell-err': '#e34948', 'cell-ink-hi': '#ffffff',
    'ink-on-amber': '#12151a',
    'ok': '#1d7a4c', 'warn': '#a35a00',
}

# The figure classes, restated as literal SVG presentation styles.
STYLE = """
<style type="text/css"><![CDATA[
  .grid  { stroke: #dfe3e9; stroke-width: 1; }
  .axis  { stroke: #c3cad4; stroke-width: 1; }
  .thr   { stroke: #767e8b; stroke-width: 1.25; stroke-dasharray: 5 4; }
  .fig-t   { font-family: 'DejaVu Sans', sans-serif; font-size: 12.5px; font-weight: 600; fill: #12151a; }
  .fig-ax  { font-family: 'DejaVu Sans', sans-serif; font-size: 11px; fill: #767e8b; }
  .fig-lab { font-family: 'DejaVu Sans', sans-serif; font-size: 11.5px; font-weight: 600; }
  .fig-thr { font-family: 'DejaVu Sans', sans-serif; font-size: 10.5px; fill: #767e8b; font-style: italic; }
  .fig-val { font-family: 'DejaVu Sans Mono', monospace; font-size: 9.5px; fill: #767e8b; }
  .fig-cell    { font-family: 'DejaVu Sans Mono', monospace; font-size: 13px; font-weight: 600; fill: #12151a; }
  .fig-cell-hi { font-family: 'DejaVu Sans Mono', monospace; font-size: 13px; font-weight: 600; fill: #ffffff; }
  .fig-cell-err{ font-family: 'DejaVu Sans Mono', monospace; font-size: 13px; font-weight: 600; fill: #ffffff; }
]]></style>
"""


def standalone(svg: str) -> str:
    svg = re.sub(r'var\(--([a-z0-9-]+)\)',
                 lambda m: TOKENS.get(m.group(1), '#000000'), svg)
    left = svg.find('>') + 1
    head = svg[:left]
    if 'xmlns' not in head:
        head = head[:-1] + ' xmlns="http://www.w3.org/2000/svg">'
    # opaque ground so the PNG does not composite onto Word's page as transparent
    vb = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', head)
    bg = (f'<rect x="0" y="0" width="{vb.group(1)}" height="{vb.group(2)}" '
          f'fill="{TOKENS["surface-2"]}"/>') if vb else ''
    return head + STYLE + bg + svg[left:]


def run():
    made = []
    for k in ['fig1', 'fig2', 'fig3', 'fig4', 'fig5', 'fig6']:
        src = open(f'{S}/{k}.svg').read()
        out = standalone(src)
        open(f'{S}/{k}_flat.svg', 'w').write(out)
        cairosvg.svg2png(bytestring=out.encode(), write_to=f'{S}/{k}.png', scale=2.4)
        made.append(k)
        print(f'{k}.png rendered')
    return made


if __name__ == '__main__':
    run()
