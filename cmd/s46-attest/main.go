package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	attest "github.com/sovereign46/attest"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "keygen":
		return runKeygen(args[1:], stdout, stderr)
	case "dev-init":
		return runDevInit(args[1:], stdout, stderr)
	case "trust-root":
		return runTrustRoot(args[1:], stdout, stderr)
	case "sign":
		return runSign(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: s46-attest <keygen|dev-init|trust-root|sign|verify> [flags]")
}

func runKeygen(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	privateKeyFile := fs.String("private-key-file", "", "path to write private key")
	publicKeyFile := fs.String("public-key-file", "", "path to write public key")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	pair, err := attest.GenerateKeyPair()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *privateKeyFile != "" {
		if err := writeFile(*privateKeyFile, []byte(pair.PrivateKey+"\n"), 0o600); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if *publicKeyFile != "" {
		if err := writeFile(*publicKeyFile, []byte(pair.PublicKey+"\n"), 0o644); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if *privateKeyFile == "" && *publicKeyFile == "" {
		body, _ := json.MarshalIndent(pair, "", "  ")
		fmt.Fprintln(stdout, string(body))
	}
	return 0
}

func runDevInit(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("dev-init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "directory for dev keys and trust root")
	witnessCount := fs.Int("witnesses", 4, "number of witness keys")
	quorum := fs.Int("quorum", 3, "witness quorum")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dir == "" {
		fmt.Fprintln(stderr, "--dir is required")
		return 2
	}
	if *witnessCount <= 0 || *quorum <= 0 || *quorum > *witnessCount {
		fmt.Fprintln(stderr, "witnesses and quorum must satisfy 0 < quorum <= witnesses")
		return 2
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	signing, err := writeNamedKey(*dir, "signing")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	submit, err := writeNamedKey(*dir, "sigsum-submit")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	logKey, err := writeNamedKey(*dir, "log")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	witnesses := make([]attest.TrustedKey, 0, *witnessCount)
	for i := 1; i <= *witnessCount; i++ {
		pair, err := writeNamedKey(*dir, "witness-"+strconv.Itoa(i))
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		witnesses = append(witnesses, attest.TrustedKey{KeyID: "witness-" + strconv.Itoa(i), PublicKey: pair.PublicKey})
	}
	root := attest.TrustRoot{
		Schema:      attest.SchemaVersion,
		SigningKeys: []attest.TrustedKey{{KeyID: "s46-build-prod", PublicKey: signing.PublicKey}},
		Sigsum: attest.SigsumTrustRoot{
			Logs:       []attest.TrustedKey{{KeyID: "log-1", PublicKey: logKey.PublicKey}},
			Witnesses:  witnesses,
			SubmitKeys: []attest.SigsumSubmitKey{{KeyID: "sigsum-submit-1", PublicKey: submit.PublicKey, SigningKeyID: "s46-build-prod"}},
			Quorum:     *quorum,
		},
		TransparencyStatus: attest.TransparencyStatus{State: attest.TransparencyOperational},
	}
	if err := attest.WriteTrustRoot(filepath.Join(*dir, "trust-root.json"), root); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote dev trust root and keys to %s\n", *dir)
	return 0
}

func runTrustRoot(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("trust-root", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "trust root JSON output path")
	keyID := fs.String("key-id", "", "signing key id")
	publicKeyFile := fs.String("public-key-file", "", "signing public key file")
	identityIssuer := fs.String("identity-issuer", "", "authorized identity issuer")
	identitySubject := fs.String("identity-subject", "", "authorized identity subject")
	policyName := fs.String("sigsum-policy", "", "named Sigsum policy to embed, e.g. sigsum-test1-2025")
	policyFile := fs.String("sigsum-policy-file", "", "Sigsum policy file to embed")
	submitPublicKeyFile := fs.String("sigsum-submit-public-key-file", "", "Sigsum submit public key file bound to --key-id")
	submitKeyID := fs.String("sigsum-submit-key-id", "", "Sigsum submit key id; defaults to <key-id>-sigsum-submit")
	expires := fs.String("expires", "", "trust root expiry as RFC3339 timestamp")
	allowEmptyIdentity := fs.Bool("allow-empty-identity", false, "allow a signing key without issuer/subject constraints")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" || *keyID == "" || *publicKeyFile == "" {
		fmt.Fprintln(stderr, "--out, --key-id, and --public-key-file are required")
		return 2
	}
	if !*allowEmptyIdentity && (*identityIssuer == "" || *identitySubject == "") {
		fmt.Fprintln(stderr, "--identity-issuer and --identity-subject are required unless --allow-empty-identity is set")
		return 2
	}
	publicKey, err := readTrimmedFile(*publicKeyFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var policyText string
	if *policyFile != "" {
		policyText, err = readTrimmedFile(*policyFile)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	var submitKeys []attest.SigsumSubmitKey
	if *submitPublicKeyFile != "" {
		submitPublicKey, err := readTrimmedFile(*submitPublicKeyFile)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		id := strings.TrimSpace(*submitKeyID)
		if id == "" {
			id = *keyID + "-sigsum-submit"
		}
		submitKeys = []attest.SigsumSubmitKey{{KeyID: id, PublicKey: submitPublicKey, SigningKeyID: *keyID, Identity: attest.Identity{Issuer: *identityIssuer, Subject: *identitySubject}}}
	}
	var expiresAt time.Time
	if *expires != "" {
		expiresAt, err = time.Parse(time.RFC3339, *expires)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	root, err := attest.NewTrustRoot(attest.TrustRootOptions{
		SigningKeys: []attest.TrustedKey{{
			KeyID:     *keyID,
			PublicKey: publicKey,
			Identity:  attest.Identity{Issuer: *identityIssuer, Subject: *identitySubject},
		}},
		SigsumPolicyName:       *policyName,
		SigsumPolicy:           policyText,
		SigsumSubmitKeys:       submitKeys,
		TransparencyStatus:     attest.TransparencyStatus{State: attest.TransparencyOperational},
		Expires:                expiresAt,
		RequireSigningIdentity: !*allowEmptyIdentity,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := attest.WriteTrustRoot(*out, root); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s\n", *out)
	return 0
}

func runSign(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "GGUF file to sign")
	bundlePath := fs.String("bundle", "", "bundle output path")
	keyID := fs.String("key-id", "", "signing key id")
	privateKeyFile := fs.String("private-key-file", "", "signing private key file")
	identityIssuer := fs.String("identity-issuer", "", "expected issuer/identity issuer")
	identitySubject := fs.String("identity-subject", "", "expected subject/identity subject")
	predicateKindRaw := fs.String("predicate-kind", string(attest.PredicateKindRelease), "predicate semantics: release, advisory, or yank")
	releaseChannel := fs.String("release-channel", "", "release channel for release predicates")
	advisoryID := fs.String("advisory-id", "", "advisory id for advisory predicates")
	advisorySeverity := fs.String("advisory-severity", "", "advisory severity")
	advisorySummary := fs.String("advisory-summary", "", "advisory summary for advisory predicates")
	advisoryURL := fs.String("advisory-url", "", "advisory URL")
	yankReason := fs.String("yank-reason", "", "reason for yank predicates")
	logPrivateKeyFile := fs.String("sigsum-log-private-key-file", "", "Sigsum log private key file")
	submitPrivateKeyFile := fs.String("sigsum-submit-private-key-file", "", "Sigsum submit private key file; use a key separate from the signing key")
	policyName := fs.String("sigsum-policy", "", "submit to live Sigsum using this named policy")
	policyFile := fs.String("sigsum-policy-file", "", "submit to live Sigsum using this policy file")
	rateLimitDomain := fs.String("sigsum-token-domain", "", "domain for Sigsum submit-token rate limiting")
	rateLimitPrivateKeyFile := fs.String("sigsum-token-private-key-file", "", "private key file for Sigsum submit-token rate limiting")
	sigsumTimeout := fs.Duration("sigsum-timeout", 10*time.Minute, "live Sigsum total submission timeout")
	sigsumRequestTimeout := fs.Duration("sigsum-request-timeout", 30*time.Second, "live Sigsum per-request timeout")
	sigsumPollDelay := fs.Duration("sigsum-poll-delay", 2*time.Second, "live Sigsum polling delay")
	var witnessKeyFiles repeatedFlag
	var yankReplacedBy repeatedFlag
	fs.Var(&witnessKeyFiles, "sigsum-witness-private-key-file", "Sigsum witness private key file; repeat for each witness cosignature")
	fs.Var(&yankReplacedBy, "yank-replaced-by", "replacement subject name or version for yank predicates; repeat as needed")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" || *bundlePath == "" || *keyID == "" || *privateKeyFile == "" {
		fmt.Fprintln(stderr, "--file, --bundle, --key-id, and --private-key-file are required")
		return 2
	}
	predicateKind, ok := parsePredicateKind(*predicateKindRaw)
	if !ok {
		fmt.Fprintf(stderr, "unsupported --predicate-kind %q\n", *predicateKindRaw)
		return 2
	}
	usesLocalSigsum := *logPrivateKeyFile != "" || len(witnessKeyFiles) > 0
	usesLiveSigsum := *policyName != "" || *policyFile != ""
	if *submitPrivateKeyFile != "" && !usesLocalSigsum && !usesLiveSigsum {
		fmt.Fprintln(stderr, "--sigsum-submit-private-key-file requires Sigsum signing options")
		return 2
	}
	if usesLocalSigsum && usesLiveSigsum {
		fmt.Fprintln(stderr, "choose either local Sigsum log/witness keys or live --sigsum-policy, not both")
		return 2
	}
	subject, err := attest.SubjectFromFile(attest.SubjectFileOptions{Path: *file, Name: filepath.Base(*file), RequireGGUF: true})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	privateKey, err := attest.ReadPrivateKeyFile(*privateKeyFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var sigsumOptions *attest.SigsumSignOptions
	var sigsumSubmitPrivateKey string
	if *submitPrivateKeyFile != "" {
		sigsumSubmitPrivateKey, err = attest.ReadPrivateKeyFile(*submitPrivateKeyFile)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if usesLiveSigsum {
		var policyText string
		if *policyFile != "" {
			policyText, err = readTrimmedFile(*policyFile)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		}
		var rateLimitPrivateKey string
		if *rateLimitPrivateKeyFile != "" {
			rateLimitPrivateKey, err = attest.ReadPrivateKeyFile(*rateLimitPrivateKeyFile)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		}
		sigsumOptions = &attest.SigsumSignOptions{
			SubmitPrivateKey:    sigsumSubmitPrivateKey,
			PolicyName:          *policyName,
			Policy:              policyText,
			RateLimitDomain:     *rateLimitDomain,
			RateLimitPrivateKey: rateLimitPrivateKey,
			Timeout:             *sigsumTimeout,
			RequestTimeout:      *sigsumRequestTimeout,
			PollDelay:           *sigsumPollDelay,
		}
	}
	if usesLocalSigsum {
		if *logPrivateKeyFile == "" || len(witnessKeyFiles) == 0 {
			fmt.Fprintln(stderr, "Sigsum signing requires a log private key and at least one witness private key")
			return 2
		}
		logKey, err := attest.ReadPrivateKeyFile(*logPrivateKeyFile)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		witnessKeys := make([]string, 0, len(witnessKeyFiles))
		for _, path := range witnessKeyFiles {
			key, err := attest.ReadPrivateKeyFile(path)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			witnessKeys = append(witnessKeys, key)
		}
		sigsumOptions = &attest.SigsumSignOptions{SubmitPrivateKey: sigsumSubmitPrivateKey, LogPrivateKey: logKey, WitnessPrivateKeys: witnessKeys, WitnessTimestamp: time.Now().UTC().Truncate(time.Second)}
	}
	bundle, err := attest.Sign(context.Background(), attest.SignOptions{
		Subjects:      []attest.Subject{subject},
		PrivateKey:    privateKey,
		KeyID:         *keyID,
		Identity:      attest.Identity{Issuer: *identityIssuer, Subject: *identitySubject},
		SignedAt:      time.Now().UTC().Truncate(time.Second),
		PredicateKind: predicateKind,
		Release:       attest.ReleasePredicate{Channel: *releaseChannel},
		Advisory: attest.AdvisoryPredicate{
			ID:       *advisoryID,
			Severity: *advisorySeverity,
			Summary:  *advisorySummary,
			URL:      *advisoryURL,
		},
		Yank:   attest.YankPredicate{Reason: *yankReason, ReplacedBy: []string(yankReplacedBy)},
		Sigsum: sigsumOptions,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := attest.WriteBundle(*bundlePath, bundle); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s\n", *bundlePath)
	return 0
}

func runVerify(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "GGUF file to verify")
	bundlePath := fs.String("bundle", "", "bundle path")
	trustRootPath := fs.String("trust-root", "", "trust root JSON path")
	keyID := fs.String("key-id", "", "expected signing key id")
	identityIssuer := fs.String("identity-issuer", "", "expected identity issuer")
	identitySubject := fs.String("identity-subject", "", "expected identity subject")
	expectedPredicateKindRaw := fs.String("predicate-kind", string(attest.PredicateKindRelease), "expected predicate semantics: release, advisory, or yank")
	strict := fs.Bool("strict", false, "fail on yellow/warning verification state")
	production := fs.Bool("production", false, "fail closed on missing, invalid, or stale transparency")
	maxWitnessAge := fs.Duration("max-witness-age", attest.DefaultWitnessMaxAge, "maximum accepted witness age")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" || *bundlePath == "" || *trustRootPath == "" {
		fmt.Fprintln(stderr, "--file, --bundle, and --trust-root are required")
		return 2
	}
	expectedPredicateKind, ok := parsePredicateKind(*expectedPredicateKindRaw)
	if !ok {
		fmt.Fprintf(stderr, "unsupported --predicate-kind %q\n", *expectedPredicateKindRaw)
		return 2
	}
	subject, err := attest.SubjectFromFile(attest.SubjectFileOptions{Path: *file, Name: filepath.Base(*file), RequireGGUF: true})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	bundle, err := attest.LoadBundle(*bundlePath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	root, err := attest.LoadTrustRoot(*trustRootPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	strictWarnings := *strict || strictFromEnv()
	mode := attest.ModeDefault
	if *production || productionFromEnv() {
		mode = attest.ModeProduction
	} else if strictWarnings {
		mode = attest.ModeStrict
	}
	result, verifyErr := attest.Verify(context.Background(), attest.VerifyRequest{
		Bundle:                bundle,
		Subjects:              []attest.Subject{subject},
		TrustRoot:             root,
		ExpectedIdentity:      attest.IdentityPolicy{KeyID: *keyID, Issuer: *identityIssuer, Subject: *identitySubject},
		ExpectedPredicateKind: expectedPredicateKind,
		Mode:                  mode,
		Strict:                strictWarnings,
		Now:                   time.Now().UTC(),
		MaxWitnessAge:         *maxWitnessAge,
	})
	body, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, string(body))
	if verifyErr != nil {
		if result.State == attest.StateWarning {
			return 2
		}
		return 1
	}
	return 0
}

type repeatedFlag []string

func (r *repeatedFlag) String() string { return strings.Join(*r, ",") }
func (r *repeatedFlag) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func parsePredicateKind(raw string) (attest.PredicateKind, bool) {
	switch attest.PredicateKind(strings.TrimSpace(raw)) {
	case "", attest.PredicateKindRelease:
		return attest.PredicateKindRelease, true
	case attest.PredicateKindAdvisory:
		return attest.PredicateKindAdvisory, true
	case attest.PredicateKindYank:
		return attest.PredicateKindYank, true
	default:
		return "", false
	}
}

func readTrimmedFile(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func writeNamedKey(dir string, name string) (attest.KeyPair, error) {
	pair, err := attest.GenerateKeyPair()
	if err != nil {
		return attest.KeyPair{}, err
	}
	if err := writeFile(filepath.Join(dir, name+".private"), []byte(pair.PrivateKey+"\n"), 0o600); err != nil {
		return attest.KeyPair{}, err
	}
	if err := writeFile(filepath.Join(dir, name+".public"), []byte(pair.PublicKey+"\n"), 0o644); err != nil {
		return attest.KeyPair{}, err
	}
	return pair, nil
}

func strictFromEnv() bool {
	return envFlag("S46_ATTEST_STRICT")
}

func productionFromEnv() bool {
	return envFlag("S46_ATTEST_PRODUCTION")
}

func envFlag(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func writeFile(path string, body []byte, mode os.FileMode) error {
	return attest.WriteFileAtomic(path, body, mode)
}
