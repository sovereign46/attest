package attest

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"
)

func TestRefreshRejectsFutureWitnessTimestamp(t *testing.T) {
	req, options, _, _ := refreshFixture(t)
	req.Now = fixedTime.Add(-time.Hour)
	if _, err := RefreshTransparency(context.Background(), req, options); err == nil {
		t.Fatal("accepted future witness timestamp")
	}
}

func TestRefreshRejectsProofForDifferentValidEnvelope(t *testing.T) {
	req, options, log, signing := refreshFixture(t)
	bundle, err := RefreshTransparency(context.Background(), req, options)
	if err != nil {
		t.Fatal(err)
	}
	// Both envelopes have valid release signatures and the same subjects. The
	// old proof must not be treated as merely missing for the changed envelope.
	_, statement, err := decodeAndValidateEnvelope(bundle.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	statement.Predicate.Release.Channel = "changed"
	payload, err := canonicalJSON(statement)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := ParsePrivateKey(signing.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Envelope.Payload = encodeBase64(payload)
	bundle.Envelope.Signatures[0].Sig = encodeBase64(ed25519.Sign(privateKey, pae(InTotoPayloadType, payload)))
	req.Bundle = bundle
	log.mu.Lock()
	before := log.addLeafCalls
	log.mu.Unlock()
	if _, err := RefreshTransparency(context.Background(), req, options); err == nil {
		t.Fatal("accepted proof bound to a different envelope")
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if log.addLeafCalls != before {
		t.Fatal("submitted envelope with invalid prior proof")
	}
}
