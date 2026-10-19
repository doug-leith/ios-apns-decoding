#!/bin/bash
# Compile report/apns_report.md to report/apns_report.pdf via pandoc, using the ACM acmart class
# (sigconf, two columns, nonacm).  The .md keeps tables and figures as raw ```{=latex} ... ```
# blocks, so no post-processing is needed.  Figures are standalone TikZ files in ../figures/,
# compiled to PDF first; Appendix B's field table is generated from ../../apns_mitm.py.
#
# Requires: pandoc, a TeX distribution (pdflatex, acmart), Python 3.
set -euo pipefail
cd "$(dirname "$0")"

OUT="apns_report"

for f in ../figures/*.tex; do
  (cd ../figures && pdflatex -interaction=nonstopmode -halt-on-error "$(basename "$f")" > /dev/null)
done
rm -f ../figures/*.aux ../figures/*.log

python3 preprocess.py
python3 ../make_field_table.py field_table.tex

pandoc _abstract.md -f markdown -t latex --wrap=preserve -o _abstract.tex

# --natbib leaves citations as \citep{key}, formatted by BibTeX with ACM-Reference-Format.
pandoc _body.md \
  -f markdown+citations+raw_tex \
  -t latex \
  --number-sections \
  --natbib \
  --syntax-highlighting=none \
  --wrap=preserve \
  -o _body.tex

cat _preamble_final.tex _abstract.tex postamble.tex _body.tex tail.tex > "${OUT}.tex"
rm -f _body.md _body.tex _abstract.md _abstract.tex _preamble_final.tex

pdflatex -interaction=nonstopmode -halt-on-error "${OUT}.tex" > /dev/null
bibtex "${OUT}" > /dev/null
pdflatex -interaction=nonstopmode -halt-on-error "${OUT}.tex" > /dev/null
pdflatex -interaction=nonstopmode -halt-on-error "${OUT}.tex" > /dev/null

cp "${OUT}.pdf" ../apns_report.pdf
echo "Done: report/apns_report.pdf"
