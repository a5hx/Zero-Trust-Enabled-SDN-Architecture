# Build the paper. Requires pdflatex + bibtex (TeX Live). No network.
#
# Figures are referenced at their SOURCE paths (see \graphicspath in
# paper.tex), so a regenerated plot in ../ppt/figures/, ../base_model/ or
# ../data/figures/ updates the paper on the next build. Nothing is copied.

PAPER = paper

all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex references.bib ieeeish.sty
	pdflatex -interaction=nonstopmode -halt-on-error $(PAPER).tex
	-bibtex $(PAPER)
	pdflatex -interaction=nonstopmode -halt-on-error $(PAPER).tex
	pdflatex -interaction=nonstopmode -halt-on-error $(PAPER).tex
	@echo
	@echo "--- undefined references / citations ---"
	@grep -n "undefined" $(PAPER).log || echo "none"
	@grep -c "Overfull" $(PAPER).log | sed 's/^/overfull boxes: /'

# Re-score every number in the paper from the archived recordings.
data: 
	./tools/regenerate.sh

clean:
	rm -f $(PAPER).aux $(PAPER).bbl $(PAPER).blg $(PAPER).log $(PAPER).out $(PAPER).toc

distclean: clean
	rm -f $(PAPER).pdf

.PHONY: all clean distclean data
