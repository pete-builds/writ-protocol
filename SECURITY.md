# Security policy

Writ is a draft protocol and a reference implementation, not a product in production use, but a flaw in either is exactly what the project most needs to hear about.

**Report privately** through GitHub's "Report a vulnerability" button on this repository's Security tab. Please do not open a public issue for something an attacker could use before it is fixed.

In scope: the specification (`docs/spec/writ-v0.1.md`), both implementations under `impl/`, and the adapters (`writ-hook`, `writ-gate`, `mcpbind`, `a2abind`). The limits stated in the spec's section 12 and in `docs/claude-code.md` are known; a way past one of them that the text does not admit is in scope.

You will get an acknowledgement, and a finding that holds up is fixed with a regression test and credited in the commit unless you ask otherwise. The project has had no independent security review yet, so a review of any part of it is welcome.
