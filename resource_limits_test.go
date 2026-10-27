package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictJSONByteDepthAndCollectionLimits(t *testing.T) {
	prefix, suffix := `{"value":"`, `"}`
	exact := []byte(prefix + strings.Repeat("x", maxJSONBytes-len(prefix)-len(suffix)) + suffix)
	if err := validateStrictJSON(exact, map[string]string{}); err != nil {
		t.Fatalf("exact JSON byte limit was rejected: %v", err)
	}
	if err := validateStrictJSON(append(exact, ' '), map[string]string{}); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("one-over JSON byte limit was accepted: %v", err)
	}

	atDepth := []byte(strings.Repeat("[", maxJSONDepth) + "0" + strings.Repeat("]", maxJSONDepth))
	if err := validateStrictJSON(atDepth, nil); err != nil {
		t.Fatalf("exact JSON depth limit was rejected: %v", err)
	}
	overDepth := []byte(strings.Repeat("[", maxJSONDepth+1) + "0" + strings.Repeat("]", maxJSONDepth+1))
	if err := validateStrictJSON(overDepth, nil); err == nil || !strings.Contains(err.Error(), "nesting exceeds") {
		t.Fatalf("one-over JSON depth limit was accepted: %v", err)
	}

	items := strings.Repeat("0,", maxJSONCollectionItems)
	atItems := []byte("[" + strings.TrimSuffix(items, ",") + "]")
	if err := validateStrictJSON(atItems, []any{}); err != nil {
		t.Fatalf("exact generic array limit was rejected: %v", err)
	}
	overItems := []byte("[" + items + "0]")
	if err := validateStrictJSON(overItems, []any{}); err == nil || !strings.Contains(err.Error(), "item limit") {
		t.Fatalf("one-over generic array limit was accepted: %v", err)
	}

	members := make([]string, maxJSONCollectionItems+1)
	for i := range members {
		members[i] = fmt.Sprintf("%q:0", fmt.Sprintf("key-%d", i))
	}
	atMembers := []byte("{" + strings.Join(members[:maxJSONCollectionItems], ",") + "}")
	if err := validateStrictJSON(atMembers, map[string]any{}); err != nil {
		t.Fatalf("exact generic object limit was rejected: %v", err)
	}
	overMembers := []byte("{" + strings.Join(members, ",") + "}")
	if err := validateStrictJSON(overMembers, map[string]any{}); err == nil || !strings.Contains(err.Error(), "member limit") {
		t.Fatalf("one-over generic object limit was accepted: %v", err)
	}
}

func TestReadJSONFileRejectsOneOverLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bounded.json")
	exact := append([]byte(`{}`), []byte(strings.Repeat(" ", maxJSONBytes-2))...)
	if err := os.WriteFile(path, exact, 0o600); err != nil {
		t.Fatal(err)
	}
	if body, err := readJSONFile(path); err != nil || len(body) != maxJSONBytes {
		t.Fatalf("exact JSON file byte limit was rejected: bytes=%d err=%v", len(body), err)
	}
	if err := os.WriteFile(path, append(exact, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readJSONFile(path); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("one-over JSON file was accepted: %v", err)
	}
}

func TestTypedInputsApplyResourceLimitsBeforeDecodingOrFingerprinting(t *testing.T) {
	root := TrustRoot{Schema: SchemaVersion, SigningKeys: make([]TrustedKey, maxJSONCollectionItems+1)}
	if err := ValidateTrustRoot(root); err == nil || !IsValidationError(err, "trust-root-resource-limit") {
		t.Fatalf("oversized typed trust root was accepted: %v", err)
	}

	bundle := Bundle{Schema: SchemaVersion, MediaType: BundleMediaType, Envelope: DSSEEnvelope{
		PayloadType: InTotoPayloadType, Payload: strings.Repeat("A", maxJSONBytes+1),
	}}
	result, err := Verify(context.Background(), VerifyRequest{Bundle: bundle})
	if err == nil || result.State != StateRefused || result.Diagnostics[0].Code != "bundle-invalid" {
		t.Fatalf("oversized typed bundle was accepted: %+v, %v", result, err)
	}
}

func TestNewTrustRootPreflightsCallerSlices(t *testing.T) {
	signing := mustKeyPair(t)
	tests := []struct {
		name    string
		options TrustRootOptions
		want    string
	}{
		{
			name:    "signing keys",
			options: TrustRootOptions{SigningKeys: make([]TrustedKey, maxJSONCollectionItems+1)},
			want:    "signingKeys",
		},
		{
			name: "submit keys",
			options: TrustRootOptions{
				SigningKeys:      []TrustedKey{{KeyID: "release", PublicKey: signing.PublicKey}},
				SigsumSubmitKeys: make([]SigsumSubmitKey, maxJSONCollectionItems+1),
			},
			want: "sigsum.submitKeys",
		},
		{
			name: "oversized policy",
			options: TrustRootOptions{
				SigningKeys:  []TrustedKey{{KeyID: "release", PublicKey: signing.PublicKey}},
				SigsumPolicy: strings.Repeat("x", maxSigsumPolicyBytes+1),
			},
			want: "sigsum policy",
		},
		{
			name: "invalid policy name",
			options: TrustRootOptions{
				SigningKeys:      []TrustedKey{{KeyID: "release", PublicKey: signing.PublicKey}},
				SigsumPolicyName: string([]byte{0xff}),
			},
			want: "invalid UTF-8",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewTrustRoot(tt.options); err == nil || !IsValidationError(err, "trust-root-resource-limit") || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("NewTrustRoot did not preflight %s: %v", tt.name, err)
			}
		})
	}
}

func TestTypedInputsRejectInvalidUTF8(t *testing.T) {
	invalid := string([]byte{0xff})
	if _, err := SubjectFromBytes(invalid, []byte("artifact")); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Fatalf("SubjectFromBytes accepted invalid UTF-8: %v", err)
	}

	signing := mustKeyPair(t)
	subject := Subject{Name: "artifact", SHA256: SHA256Bytes([]byte("artifact")), SizeBytes: 8}
	if _, err := Sign(context.Background(), SignOptions{Subjects: []Subject{subject}, PrivateKey: signing.PrivateKey, KeyID: invalid}); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Fatalf("Sign accepted invalid UTF-8 key ID: %v", err)
	}
	if _, err := Sign(context.Background(), SignOptions{
		Subjects: []Subject{subject}, PrivateKey: signing.PrivateKey, KeyID: "release",
		PredicateKind: PredicateKindAdvisory,
		Advisory:      AdvisoryPredicate{ID: "ADV-1", Summary: invalid},
	}); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Fatalf("Sign accepted invalid UTF-8 predicate: %v", err)
	}
	if _, err := NewTrustRoot(TrustRootOptions{SigningKeys: []TrustedKey{{KeyID: invalid, PublicKey: signing.PublicKey}}}); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Fatalf("NewTrustRoot accepted invalid UTF-8 key ID: %v", err)
	}

	req, _ := deterministicVerifyFixture(t)
	req.Bundle.Envelope.Signatures[0].KeyID = invalid
	result, err := Verify(context.Background(), req)
	if err == nil || result.State != StateRefused || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "bundle-invalid" || !strings.Contains(result.Diagnostics[0].Message, "invalid UTF-8") {
		t.Fatalf("Verify accepted invalid UTF-8 typed bundle: %+v, %v", result, err)
	}

	req, _ = deterministicVerifyFixture(t)
	req.Subjects[0].Name = invalid
	result, err = Verify(context.Background(), req)
	if err == nil || result.State != StateRefused || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "attestation-invalid" || !strings.Contains(result.Diagnostics[0].Message, "invalid UTF-8") {
		t.Fatalf("Verify accepted invalid UTF-8 expected subject: %+v, %v", result, err)
	}
}

func TestTypedAndProducerInputsUseCumulativeJSONBudget(t *testing.T) {
	shared := strings.Repeat("\x01", maxSecurityStringBytes)

	bundle := Bundle{Schema: SchemaVersion, MediaType: BundleMediaType, Envelope: DSSEEnvelope{
		PayloadType: InTotoPayloadType, Payload: "AA",
		Signatures: make([]EnvelopeSignature, 400),
	}}
	for index := range bundle.Envelope.Signatures {
		bundle.Envelope.Signatures[index] = EnvelopeSignature{KeyID: shared, Sig: shared}
	}
	if err := validateBundleResourceBounds(bundle); err == nil || !strings.Contains(err.Error(), "bundle JSON exceeds") {
		t.Fatalf("cumulatively oversized typed bundle was accepted: %v", err)
	}

	key := TrustedKey{KeyID: shared, PublicKey: shared, URL: shared, Identity: Identity{Issuer: shared, Subject: shared}}
	root := TrustRoot{Schema: SchemaVersion, SigningKeys: make([]TrustedKey, 140)}
	for index := range root.SigningKeys {
		root.SigningKeys[index] = key
	}
	if err := ValidateTrustRoot(root); err == nil || !IsValidationError(err, "trust-root-resource-limit") || !strings.Contains(err.Error(), "trust root JSON exceeds") {
		t.Fatalf("cumulatively oversized typed trust root was accepted: %v", err)
	}
	if _, err := NewTrustRoot(TrustRootOptions{SigningKeys: root.SigningKeys}); err == nil || !IsValidationError(err, "trust-root-resource-limit") || !strings.Contains(err.Error(), "trust root JSON exceeds") {
		t.Fatalf("NewTrustRoot cloned cumulatively oversized options before rejection: %v", err)
	}

	signing := mustKeyPair(t)
	subject := Subject{Name: "artifact", SHA256: SHA256Bytes([]byte("artifact")), SizeBytes: 8}
	replacements := make([]string, 700)
	for index := range replacements {
		replacements[index] = shared
	}
	if _, err := Sign(context.Background(), SignOptions{
		Subjects: []Subject{subject}, PrivateKey: signing.PrivateKey, KeyID: "release",
		PredicateKind: PredicateKindYank,
		Yank:          YankPredicate{Reason: "superseded", ReplacedBy: replacements},
	}); err == nil || !strings.Contains(err.Error(), "statement JSON exceeds") {
		t.Fatalf("cumulatively oversized statement reached marshaling: %v", err)
	}
}

func TestJSONSizeBudgetsCoverProducerEncoding(t *testing.T) {
	nearLimit := Bundle{Schema: SchemaVersion, MediaType: BundleMediaType, Envelope: DSSEEnvelope{
		PayloadType: InTotoPayloadType, Signatures: []EnvelopeSignature{{KeyID: "k", Sig: "s"}},
	}}
	emptyPayloadBound, err := bundleJSONSizeUpperBound(nearLimit)
	if err != nil {
		t.Fatal(err)
	}
	nearLimit.Envelope.Payload = strings.Repeat("A", maxJSONBytes-emptyPayloadBound)
	if bound, err := bundleJSONSizeUpperBound(nearLimit); err != nil || bound != maxJSONBytes {
		t.Fatalf("near-limit bundle upper bound = %d, %v", bound, err)
	}
	if _, err := MarshalBundle(nearLimit); err != nil {
		t.Fatalf("producer rejected bundle at preflight budget: %v", err)
	}
	nearLimit.Envelope.Payload += "A"
	if err := validateBundleResourceBounds(nearLimit); err == nil || !strings.Contains(err.Error(), "bundle JSON exceeds") {
		t.Fatalf("producer accepted bundle over preflight budget: %v", err)
	}

	bundle := Bundle{Schema: SchemaVersion, MediaType: BundleMediaType, Envelope: DSSEEnvelope{
		PayloadType: InTotoPayloadType, Payload: "AA",
		Signatures: make([]EnvelopeSignature, maxJSONCollectionItems),
	}, Sigsum: &SigsumProof{Proof: "proof"}}
	for index := range bundle.Envelope.Signatures {
		bundle.Envelope.Signatures[index] = EnvelopeSignature{KeyID: "k", Sig: "s"}
	}
	bundleBound, err := bundleJSONSizeUpperBound(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundleJSON, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if actual := len(bundleJSON) + 1; actual > bundleBound {
		t.Fatalf("bundle JSON size %d exceeds preflight upper bound %d", actual, bundleBound)
	}

	trustedKeys := make([]TrustedKey, maxJSONCollectionItems)
	for index := range trustedKeys {
		trustedKeys[index] = TrustedKey{KeyID: "k", PublicKey: "p", URL: "u", Identity: Identity{Issuer: "i", Subject: "s"}}
	}
	submitKeys := make([]SigsumSubmitKey, maxJSONCollectionItems)
	for index := range submitKeys {
		submitKeys[index] = SigsumSubmitKey{KeyID: "k", PublicKey: "p", SigningKeyID: "s", Identity: Identity{Issuer: "i", Subject: "s"}}
	}
	revocations := make([]IdentityRevocation, maxJSONCollectionItems)
	for index := range revocations {
		revocations[index] = IdentityRevocation{Issuer: "i", Subject: "s", RevokedSince: fixedTime, Reason: "r"}
	}
	root := TrustRoot{
		Schema: SchemaVersion, SigningKeys: trustedKeys,
		Sigsum:              SigsumTrustRoot{PolicyName: "policy", Policy: "policy", Logs: trustedKeys, Witnesses: trustedKeys, SubmitKeys: submitKeys, Quorum: 1},
		TransparencyStatus:  TransparencyStatus{State: TransparencyOperational, Reason: "ok", Since: fixedTime},
		IdentityRevocations: revocations, Expires: fixedTime, RequireSigningIdentity: true,
	}
	rootBound, err := trustRootJSONSizeUpperBound(root)
	if err != nil {
		t.Fatal(err)
	}
	rootJSON, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if actual := len(rootJSON) + 1; actual > rootBound {
		t.Fatalf("trust-root JSON size %d exceeds preflight upper bound %d", actual, rootBound)
	}

	digests := make(map[string]string, MaxSubjectDigests)
	for index := 0; index < MaxSubjectDigests; index++ {
		digests[fmt.Sprintf("digest-%d", index)] = "value"
	}
	subjects := make([]ResourceDescriptor, MaxStatementSubjects)
	for index := range subjects {
		subjects[index] = ResourceDescriptor{Name: "subject", Digest: digests, Size: 1}
	}
	statement := Statement{
		Type: InTotoStatementType, Subject: subjects, PredicateType: S46PredicateType,
		Predicate: Predicate{
			BuildType: S46YankBuildType, Kind: PredicateKindYank, SignedAt: fixedTime,
			Signer: Signer{KeyID: "release", Algorithm: SignatureAlgorithm, Identity: Identity{Issuer: "issuer", Subject: "subject"}},
			Yank:   &YankPredicate{Reason: "reason", ReplacedBy: make([]string, maxJSONCollectionItems)},
		},
	}
	for index := range statement.Predicate.Yank.ReplacedBy {
		statement.Predicate.Yank.ReplacedBy[index] = "replacement"
	}
	statementBound, err := statementJSONSizeUpperBound(statement)
	if err != nil {
		t.Fatal(err)
	}
	statementJSON, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	if actual := len(statementJSON); actual > statementBound {
		t.Fatalf("statement JSON size %d exceeds preflight upper bound %d", actual, statementBound)
	}
}

func TestTypedTrustRootBoundsTransparencyState(t *testing.T) {
	root := TrustRoot{
		Schema:             SchemaVersion,
		SigningKeys:        []TrustedKey{{KeyID: "release", PublicKey: mustKeyPair(t).PublicKey}},
		TransparencyStatus: TransparencyStatus{State: TransparencyState(strings.Repeat("x", maxSecurityStringBytes+1))},
	}
	if err := ValidateTrustRoot(root); err == nil || !IsValidationError(err, "trust-root-resource-limit") || !strings.Contains(err.Error(), "transparencyStatus") {
		t.Fatalf("oversized transparency state was accepted: %v", err)
	}
}

func TestNamedSigsumPolicyReadIsBounded(t *testing.T) {
	source := bytes.NewReader(make([]byte, maxSigsumPolicyBytes+4096))
	if _, err := readBoundedSigsumPolicy(source); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("oversized policy reader was accepted: %v", err)
	}
	if consumed := maxSigsumPolicyBytes + 4096 - source.Len(); consumed != maxSigsumPolicyBytes+1 {
		t.Fatalf("bounded policy reader consumed %d bytes, want %d", consumed, maxSigsumPolicyBytes+1)
	}

	directory := t.TempDir()
	t.Setenv("SIGSUM_POLICY_DIR", directory)
	path := filepath.Join(directory, "oversized-policy.sigsum-policy")
	if err := os.WriteFile(path, []byte(strings.Repeat("#", maxSigsumPolicyBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SigsumTrustRootFromPolicy("oversized-policy", ""); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("oversized named policy was read without a limit: %v", err)
	}
}

func TestSigsumPolicyLineLimitPreventsParserTruncation(t *testing.T) {
	log := mustKeyPair(t)
	witness := mustKeyPair(t)
	prefix := fmt.Sprintf("log %s\nwitness witness %s\ngroup witnesses all witness\nquorum witnesses\n",
		trustedKeyHex(t, TrustedKey{PublicKey: log.PublicKey}),
		trustedKeyHex(t, TrustedKey{PublicKey: witness.PublicKey}))

	atLimit := prefix + strings.Repeat("#", maxSigsumPolicyLineBytes) + "\n"
	if _, err := SigsumTrustRootFromPolicy("", atLimit); err != nil {
		t.Fatalf("policy line at limit was rejected: %v", err)
	}

	overLimit := prefix + strings.Repeat("#", maxSigsumPolicyLineBytes+1) + "\nthis is invalid policy syntax\n"
	if _, err := SigsumTrustRootFromPolicy("", overLimit); err == nil || !strings.Contains(err.Error(), "policy line exceeds") {
		t.Fatalf("embedded policy was silently truncated at oversized line: %v", err)
	}

	directory := t.TempDir()
	t.Setenv("SIGSUM_POLICY_DIR", directory)
	if err := os.WriteFile(filepath.Join(directory, "line-limit.sigsum-policy"), []byte(overLimit), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SigsumTrustRootFromPolicy("line-limit", ""); err == nil || !strings.Contains(err.Error(), "policy line exceeds") {
		t.Fatalf("named policy was silently truncated at oversized line: %v", err)
	}
}

func TestSigsumTrustRootFromPolicyAppliesConsumerBounds(t *testing.T) {
	log := mustKeyPair(t)
	witness := mustKeyPair(t)
	oversizedURL := "https://example.com/" + strings.Repeat("x", maxSecurityStringBytes)
	policy := fmt.Sprintf("log %s %s\nwitness witness %s\ngroup witnesses all witness\nquorum witnesses\n",
		trustedKeyHex(t, TrustedKey{PublicKey: log.PublicKey}), oversizedURL,
		trustedKeyHex(t, TrustedKey{PublicKey: witness.PublicKey}))
	if _, err := SigsumTrustRootFromPolicy("", policy); err == nil || !strings.Contains(err.Error(), "generated Sigsum trust root") || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("Sigsum trust-root producer returned consumer-invalid fields: %v", err)
	}
}

func TestSigsumPolicyAndProofComplexityLimits(t *testing.T) {
	var policy strings.Builder
	policy.WriteString("witness w0 key\n")
	previous := "w0"
	for i := 1; i <= maxSigsumPolicyDepth; i++ {
		name := "g" + strings.Repeat("x", i)
		policy.WriteString("group " + name + " all " + previous + "\n")
		previous = name
	}
	if err := validateSigsumPolicyComplexity(policy.String()); err == nil || !strings.Contains(err.Error(), "nesting exceeds") {
		t.Fatalf("over-depth policy was accepted: %v", err)
	}

	proof := strings.Repeat("cosignature=x\n", maxJSONCollectionItems+1)
	if err := validateSigsumProofResourceBounds(proof); err == nil || !strings.Contains(err.Error(), "cosignature limit") {
		t.Fatalf("over-limit cosignature set was accepted: %v", err)
	}
}
