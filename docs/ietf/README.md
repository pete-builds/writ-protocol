# The Internet-Draft

`draft-stergion-writ-00.md` is the specification in Internet-Draft form, in kramdown-rfc markdown. It is generated, never edited by hand:

```
python3 scripts/build-ietf-draft.py
```

The generator takes the abstract, the text, and the appendices from `docs/spec/writ-v0.1.md`, and adds `front.md` (title, author, references), `implementation-status.md` (the implementation status section of RFC 7942, to be removed before publication), and `iana.md` (a media type registration and two new registries). The introduction opens section 1, and the implementation status and IANA considerations follow section 14, so every "section N" in the text still points at the right section. CI regenerates the draft and fails if the committed copy differs from what the spec produces.

Rendering needs the IETF tools, kramdown-rfc and xml2rfc:

```
kramdown-rfc docs/ietf/draft-stergion-writ-00.md > draft.xml
xml2rfc --text --html draft.xml --path .
```

On 2026-09-30 this rendered with no errors and two warnings, both lines in JSON examples longer than 72 characters. The section numbers in the rendered draft match the spec's.

**Status: not submitted.** The roadmap submits an individual draft only after an independent implementation and a production pair between two organizations; submitting is the author's decision.
