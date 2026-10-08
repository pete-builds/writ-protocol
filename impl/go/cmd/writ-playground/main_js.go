//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"
)

// main exposes writPlay(scenario, limitCents) to the page. It returns the
// outcome as a JSON string, or {"error": "..."}, and keeps running so the
// page can call it again.
func main() {
	js.Global().Set("writPlay", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return `{"error":"writPlay(scenario, limitCents)"}`
		}
		o, err := Play(args[0].String(), int64(args[1].Int()))
		if err != nil {
			b, _ := json.Marshal(map[string]string{"error": err.Error()})
			return string(b)
		}
		b, _ := json.Marshal(o)
		return string(b)
	}))
	js.Global().Call("dispatchEvent", js.Global().Get("Event").New("writ-ready"))
	select {}
}
