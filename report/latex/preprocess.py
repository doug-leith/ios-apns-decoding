#!/usr/bin/env python3
"""Split ../apns_report.md into title, abstract and body for build.sh.

The header block is `# Title`, an author paragraph, `**Abstract**` and the abstract paragraph(s),
up to the first `#`/`##` heading.  The abstract gets its own pandoc pass; the title is synced into
\\title{...} in preamble.tex.
"""
import re
import sys

SRC = "../apns_report.md"

with open(SRC, encoding="utf-8") as f:
    text = f.read()

m = re.match(
    r"^# (?P<title>.*?)\s*\n\n(?P<author>.*?)\n\n\*\*Abstract\*\*\n\n(?P<abstract>.*?)\n\n(?=#{1,2} )",
    text, flags=re.DOTALL,
)
if not m:
    sys.exit("FATAL: could not parse the title/author/abstract header block")

with open("_abstract.md", "w", encoding="utf-8") as f:
    f.write(m.group("abstract").strip())
with open("_body.md", "w", encoding="utf-8") as f:
    f.write(text[m.end():])

with open("preamble.tex", encoding="utf-8") as f:
    preamble = f.read()
preamble, n = re.subn(r"\\title\{.*?\}", lambda _: "\\title{" + m.group("title").strip() + "}", preamble, count=1)
assert n == 1, "no \\title{...} in preamble.tex"
# the last line of the author block is the report date, printed under the email as a second
# affiliation (acmart prints no \date)
date = m.group("author").strip().splitlines()[-1].strip()
preamble, n = re.subn(r"\\affiliation\{\\institution\{DATE\}\\country\{\}\}", lambda _: "\\affiliation{\\institution{" + date + "}\\country{}}", preamble, count=1)
assert n == 1, "no \\affiliation{\\institution{DATE}\\country{}} in preamble.tex"
with open("_preamble_final.tex", "w", encoding="utf-8") as f:
    f.write(preamble)
print("preprocess: title, abstract and body written")
