package main

import (
	"reflect"
	"testing"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/protocol"
)

func TestBaselineReproduciblePlan(t *testing.T) {
	var previous string
	for _, seed := range []int{1109, 1110, 1111, 1112, 1113} {
		a, err := Baseline(seed)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Baseline(seed)
		if err != nil {
			t.Fatal(err)
		}
		da, err := a.Digest()
		if err != nil {
			t.Fatal(err)
		}
		db, err := b.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if da != db || !reflect.DeepEqual(a.Cases, b.Cases) {
			t.Fatal("same seed changed logical inputs")
		}
		if da == previous {
			t.Fatal("different seed did not change fixture digest")
		}
		previous = da
		if len(a.Cases) != 12 {
			t.Fatalf("got %d cases", len(a.Cases))
		}
		for n, c := range a.Cases {
			if c.Configuration != []string{"C0", "B0", "B1"}[n/4] || c.Mode != []string{api.RP, api.BM}[(n%4)/2] || c.AmountMinor != []int64{80000, 120000}[n%2] {
				t.Fatalf("wrong execution order: %+v", c)
			}
			if c.ExpectedStatus != []int{200, 403}[n%2] {
				t.Fatalf("wrong order expectation: %+v", c)
			}
			if c.CaseID != a.Cases[n%4].CaseID {
				t.Fatal("configurations are not paired")
			}
		}
		if a.Fixture.TimeRules.ChallengeTTL != gateway.ChallengeTTLSeconds || a.Fixture.TimeRules.ProbeLifetime != int64(api.ProbeLifetime.Seconds()) || a.Fixture.TimeRules.ProbeInterval != int64(api.ProbeInterval.Seconds()) {
			t.Fatal("frozen deadlines drifted from runtime")
		}
	}
	if _, err := Baseline(42); err == nil {
		t.Fatal("accepted unplanned seed")
	}
}

func TestBaselineHasNoRandomState(t *testing.T) {
	first, _ := Baseline(1109)
	digest, _ := first.Digest()
	first.Fixture.Domains["A"] = "mutated"
	again, _ := Baseline(1109)
	after, _ := again.Digest()
	if digest != after {
		t.Fatal("shared mutable fixture")
	}
	// Planning neither consumes nor supplies entropy to the protocol nonce generator.
	n1, err := protocol.GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = Baseline(1109)
	n2, err := protocol.GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	if n1 == n2 {
		t.Fatal("challenge randomness reused")
	}
}

func TestBaselineConfigurations(t *testing.T) {
	for _, want := range []Configuration{
		{Name: "C0", StateSource: gateway.StateCentralized},
		{Name: "B0", StateSource: gateway.StateFabric},
		{Name: "B1", StateSource: gateway.StateFabric, SignatureCache: true},
	} {
		got, err := BaselineConfiguration(want.Name)
		if err != nil || got != want || (got.NewSignatureCache() != nil) != want.SignatureCache {
			t.Fatalf("%s configuration: got %+v, error %v", want.Name, got, err)
		}
	}
}
