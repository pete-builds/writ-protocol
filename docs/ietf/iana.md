
# IANA Considerations

## Media Type

This document requests registration of the media type `application/writ+json` in the "Media Types" registry {{RFC6838}}, for a single Writ call, tally, or revoke object in the canonical JSON form of section 1.2 (section 10). Type name: application. Subtype name: writ+json. Required parameters: none. Optional parameters: none. Encoding considerations: binary; the content is UTF-8 JSON. Security considerations: see section 12. Interoperability considerations: see section 14. Published specification: this document.

## Writ Bound Types

This document requests a new registry, "Writ Bound Types", with the policy Specification Required. Each entry names a bound type and points to the specification that defines its comparison for narrowing and its test against an argument (section 3). The initial entries are `max`, `count`, `prefix`, `set`, and `window`, defined by this document.

## Writ Reason Codes

This document requests a new registry, "Writ Reason Codes", with the policy Specification Required, holding the codes of section 11 and their meanings. Codes outside the registry are application codes and carry a namespace prefix (section 11).
