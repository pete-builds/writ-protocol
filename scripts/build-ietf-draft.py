#!/usr/bin/env python3
"""Build docs/ietf/draft-stergion-writ-00.md (kramdown-rfc) from the spec.

The spec is the source; the draft is generated so the two cannot drift.
Section numbers are kept: the introduction is unnumbered and IANA
considerations come after section 14, so every "section N" in the text still
points at the right place. Render with kramdown-rfc and xml2rfc.
"""
import os
import re
import sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = open(os.path.join(root, "docs/spec/writ-v0.1.md"), encoding="utf-8").read()
front = open(os.path.join(root, "docs/ietf/front.md"), encoding="utf-8").read()
iana = open(os.path.join(root, "docs/ietf/iana.md"), encoding="utf-8").read()
status = open(os.path.join(root, "docs/ietf/implementation-status.md"), encoding="utf-8").read()

abstract_start = spec.index("## Abstract\n")
conventions = spec.index("## 1. Conventions\n")
appendix = spec.index("## Appendix A.")
before = spec[abstract_start + len("## Abstract\n"):conventions].strip().split("\n\n")
abstract, intro = before[0], "\n\n".join(before[1:])
body, back = spec[conventions:appendix], spec[appendix:]

cited = ["RFC2119", "RFC8174", "RFC8032", "RFC8785", "RFC4648", "RFC7515", "RFC9396"]


def cite(text):
    for ref in cited:
        text = re.sub(r"\bRFC " + ref[3:] + r"\b", "{{" + ref + "}}", text)
    return text.replace("{{RFC2119}} and {{RFC8174}}", "BCP 14 {{RFC2119}} {{RFC8174}}")


def headings(text, appendix=False):
    out = []
    for line in text.split("\n"):
        m = re.match(r"^## (?:Appendix [A-Z]\.|\d+\.)\s+(.*)$", line)
        if m:
            out.append("# " + m.group(1))
            continue
        m = re.match(r"^### \d+\.\d+\s+(.*)$", line)
        if m:
            out.append("## " + m.group(1))
            continue
        out.append(line)
    return "\n".join(out)


# The introduction opens section 1, so every section keeps its number.
body = body.replace("## 1. Conventions\n", "## 1. Introduction and Conventions\n\n" + intro + "\n\n"
                    "This document is generated from docs/spec/writ-v0.1.md in the repository at "
                    "https://github.com/pete-builds/writ-protocol, which also holds two implementations and "
                    "a conformance corpus. Section numbers match that text.\n", 1)
body = body.replace("A principal is identified by a did:key for an Ed25519 public key",
                    "A principal is identified by a did:key {{DID-KEY}} for an Ed25519 public key", 1)
body = cite(headings(body)).replace(
    "The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY are to be interpreted as in BCP 14 {{RFC2119}} {{RFC8174}}.",
    "{::boilerplate bcp14-tagged}",
)
draft = (front.replace("@@ABSTRACT@@", cite(abstract))
         + "\n" + body.rstrip() + "\n" + status + "\n" + iana + "\n--- back\n\n" + cite(headings(back)).strip() + "\n")
if "@@" in draft:
    sys.exit("a placeholder was left unfilled")
out = os.path.join(root, "docs/ietf/draft-stergion-writ-00.md")
open(out, "w", encoding="utf-8").write(draft)
print("wrote", os.path.relpath(out, root))
