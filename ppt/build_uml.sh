#!/usr/bin/env bash
# Render every ppt/uml/*.puml to ppt/figures/uml_<name>.png
# Needs Java only: PlantUML's Smetana engine replaces Graphviz, which is not
# installed on this box. Fetch the jar once with:
#   curl -L -o ppt/tools/plantuml.jar \
#     https://repo1.maven.org/maven2/net/sourceforge/plantuml/plantuml/1.2025.10/plantuml-1.2025.10.jar
set -euo pipefail
cd "$(dirname "$0")"
JAR=tools/plantuml.jar
[ -f "$JAR" ] || { echo "missing $JAR -- see the header of this script" >&2; exit 1; }

for f in uml/*.puml; do
  base=$(basename "$f" .puml)
  [ "$base" = "_style" ] && continue
  java -jar "$JAR" -tpng -nometadata -o "$PWD/figures" "$f"
  # PlantUML names the output after the @startuml id; normalise to uml_<name>.png
  [ -f "figures/$base.png" ] && mv -f "figures/$base.png" "figures/uml_$base.png"
  echo "  figures/uml_$base.png"
done
echo "done."
