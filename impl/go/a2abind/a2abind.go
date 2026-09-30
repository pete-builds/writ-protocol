// Package a2abind carries Writ over A2A, as docs/adoption.md section 2b
// designs it. A call rides in a request message as a data part of media type
// application/writ-call+json, or in message.metadata["io.writ/call"] for a
// client that cannot add parts; the tally returns as the task's last
// artifact, a data part of application/writ-tally+json, and the terminal
// status message repeats its identity in metadata["io.writ/tally"]. A revoke
// rides on CancelTask in message.metadata["io.writ/revoke"]. The functions
// work on decoded JSON, so they fit any A2A server or client.
package a2abind

import (
	"encoding/json"
	"errors"

	"writproto/wire"
)

const (
	CallType   = "application/writ-call+json"
	TallyType  = "application/writ-tally+json"
	CallKey    = "io.writ/call"
	TallyKey   = "io.writ/tally"
	RevokeKey  = "io.writ/revoke"
	ExtURI     = "https://writ.dev/ext/delegation/v1"
	FormPart   = "part"
	FormMetaKV = "metadata"
)

// ErrNoCall: the message carries no Writ call in either form.
var ErrNoCall = errors.New("a2abind: the message carries no Writ call")

// CallFrom returns the Writ call a message carries and the form it came in,
// so the server can answer in the same shape. The data part is preferred.
func CallFrom(message map[string]any) (wire.Object, string, error) {
	parts, _ := message["parts"].([]any)
	for _, p := range parts {
		part, _ := p.(map[string]any)
		meta, _ := part["metadata"].(map[string]any)
		if meta["mimeType"] == CallType {
			obj, err := decode(part["data"])
			return obj, FormPart, err
		}
	}
	meta, _ := message["metadata"].(map[string]any)
	if raw, ok := meta[CallKey]; ok {
		obj, err := decode(raw)
		return obj, FormMetaKV, err
	}
	return nil, "", ErrNoCall
}

// RevokeFrom returns the Writ revoke a CancelTask message carries, if any.
func RevokeFrom(message map[string]any) (wire.Object, bool, error) {
	meta, _ := message["metadata"].(map[string]any)
	raw, ok := meta[RevokeKey]
	if !ok {
		return nil, false, nil
	}
	obj, err := decode(raw)
	return obj, true, err
}

// CallPart is the data part a client adds to its request message.
func CallPart(call wire.Object) map[string]any {
	return map[string]any{"kind": "data", "data": call, "metadata": map[string]any{"mimeType": CallType}}
}

// TallyArtifact is the artifact that carries a tally; emit it last before the
// terminal state.
func TallyArtifact(artifactID string, tally wire.Object) map[string]any {
	return map[string]any{
		"artifactId": artifactID,
		"name":       "writ-tally",
		"parts":      []any{map[string]any{"kind": "data", "data": tally, "metadata": map[string]any{"mimeType": TallyType}}},
	}
}

// StatusMetadata is the metadata for the terminal status message: the
// tally's identity, so a client that missed the artifact can fetch it.
func StatusMetadata(tally wire.Object) (map[string]any, error) {
	id, err := wire.Hash(tally)
	if err != nil {
		return nil, err
	}
	return map[string]any{TallyKey: id}, nil
}

// TallyFrom returns the tally in a task's artifacts, the last one of its type.
func TallyFrom(artifacts []any) (wire.Object, error) {
	var found any
	for _, a := range artifacts {
		art, _ := a.(map[string]any)
		parts, _ := art["parts"].([]any)
		for _, p := range parts {
			part, _ := p.(map[string]any)
			if meta, _ := part["metadata"].(map[string]any); meta["mimeType"] == TallyType {
				found = part["data"]
			}
		}
	}
	if found == nil {
		return nil, errors.New("a2abind: no tally artifact")
	}
	return decode(found)
}

// CardExtension is the Agent Card entry for capabilities.extensions. The card
// is JWS-signed under the vendor's domain, so it binds the key to the vendor.
func CardExtension(did string, bounds []string, maxChain int) map[string]any {
	b := make([]any, len(bounds))
	for i, x := range bounds {
		b[i] = x
	}
	return map[string]any{"uri": ExtURI, "description": "Writ delegation and tally", "required": false,
		"params": map[string]any{"did": did, "bounds": b, "maxChain": maxChain}}
}

func decode(v any) (wire.Object, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return wire.Decode(b)
}
