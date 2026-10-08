package main

import (
	"strings"
	"testing"
)

func play(t *testing.T, s string) *Outcome {
	t.Helper()
	o, err := Play(s, 60000)
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return o
}

func TestHonestBookingVerifies(t *testing.T) {
	o := play(t, "honest")
	if o.Verdict != "ok" || o.Charges != 1 || o.Objects["tally_B"] == nil || o.Objects["writ_2"] == nil {
		t.Fatalf("%+v", o)
	}
}

func TestWiderSlipIsRefused(t *testing.T) {
	o := play(t, "widen")
	last := o.Steps[len(o.Steps)-2]
	if o.Verdict != "refused" || o.Charges != 0 || last.Code == "" {
		t.Fatalf("%+v", o)
	}
}

func TestOverchargeIsRefusedByC(t *testing.T) {
	o := play(t, "overspend")
	refused := false
	for _, s := range o.Steps {
		if s.Who == "C" && s.Code == "out_of_bounds" {
			refused = true
		}
	}
	if o.Verdict != "refused" || o.Charges != 0 || !refused {
		t.Fatalf("%+v", o)
	}
}

func TestReplayReturnsTheSameReceipt(t *testing.T) {
	o := play(t, "replay")
	last := o.Steps[len(o.Steps)-1]
	if o.Verdict != "same" || o.Charges != 1 || !last.OK || !strings.Contains(last.Text, "(true)") {
		t.Fatalf("%+v", o)
	}
}

func TestForgedReceiptIsCaught(t *testing.T) {
	o := play(t, "forge")
	last := o.Steps[len(o.Steps)-1]
	if o.Verdict != "caught" || !last.OK || last.Code != "signed_unauthorized" || !strings.Contains(last.Text, "bad_signature") {
		t.Fatalf("%+v", o)
	}
}

func TestUndoWithoutBRefundsOnce(t *testing.T) {
	o := play(t, "crash")
	last := o.Steps[len(o.Steps)-1]
	if o.Verdict != "ok" || o.Refunds != 1 || !last.OK {
		t.Fatalf("%+v", o)
	}
}

func TestLimitIsChecked(t *testing.T) {
	if _, err := Play("honest", 5); err == nil {
		t.Fatal("a $0.05 limit was accepted")
	}
	if _, err := Play("nope", 60000); err == nil {
		t.Fatal("an unknown scenario ran")
	}
}
