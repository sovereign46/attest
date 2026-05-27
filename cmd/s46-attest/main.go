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

	attest "github.com/sovereign46/s46-attest"
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
			Logs:      []attest.TrustedKey{{KeyID: "log-1", PublicKey: logKey.PublicKey}},
			Witnesses: witnesses,
			Quorum:    *quorum,
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
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" || *keyID == "" || *publicKeyFile == "" {
		fmt.Fprintln(stderr, "--out, --key-id, and --public-key-file are required")
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
	root, err := attest.NewTrustRoot(attest.TrustRootOptions{
		SigningKeys: []attest.TrustedKey{{
			KeyID:     *keyID,
			PublicKey: publicKey,
			Identity:  attest.Identity{Issuer: *identityIssuer, Subject: *identitySubject},
		}},
		SigsumPolicyName:   *policyName,
		SigsumPolicy:       policyText,
		TransparencyStatus: attest.TransparencyStatus{State: attest.TransparencyOperational},
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
	logPrivateKeyFile := fs.String("sigsum-log-private-key-file", "", "Sigsum log private key file")
	policyName := fs.String("sigsum-policy", "", "submit to live Sigsum using this named policy")
	policyFile := fs.String("sigsum-policy-file", "", "submit to live Sigsum using this policy file")
	rateLimitDomain := fs.String("sigsum-token-domain", "", "domain for Sigsum submit-token rate limiting")
	rateLimitPrivateKeyFile := fs.String("sigsum-token-private-key-file", "", "private key file for Sigsum submit-token rate limiting")
	sigsumTimeout := fs.Duration("sigsum-timeout", 10*time.Minute, "live Sigsum total submission timeout")
	sigsumRequestTimeout := fs.Duration("sigsum-request-timeout", 30*time.Second, "live Sigsum per-request timeout")
	sigsumPollDelay := fs.Duration("sigsum-poll-delay", 2*time.Second, "live Sigsum polling delay")
	var witnessKeyFiles repeatedFlag
	fs.Var(&witnessKeyFiles, "sigsum-witness-private-key-file", "Sigsum witness private key file; repeat for each witness cosignature")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" || *bundlePath == "" || *keyID == "" || *privateKeyFile == "" {
		fmt.Fprintln(stderr, "--file, --bundle, --key-id, and --private-key-file are required")
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
	usesLocalSigsum := *logPrivateKeyFile != "" || len(witnessKeyFiles) > 0
	usesLiveSigsum := *policyName != "" || *policyFile != ""
	if usesLocalSigsum && usesLiveSigsum {
		fmt.Fprintln(stderr, "choose either local Sigsum log/witness keys or live --sigsum-policy, not both")
		return 2
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
		sigsumOptions = &attest.SigsumSignOptions{LogPrivateKey: logKey, WitnessPrivateKeys: witnessKeys, WitnessTimestamp: time.Now().UTC().Truncate(time.Second)}
	}
	bundle, err := attest.Sign(context.Background(), attest.SignOptions{
		Subjects:   []attest.Subject{subject},
		PrivateKey: privateKey,
		KeyID:      *keyID,
		Identity:   attest.Identity{Issuer: *identityIssuer, Subject: *identitySubject},
		SignedAt:   time.Now().UTC().Truncate(time.Second),
		Sigsum:     sigsumOptions,
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
	strict := fs.Bool("strict", false, "fail on yellow/warning verification state")
	maxWitnessAge := fs.Duration("max-witness-age", attest.DefaultWitnessMaxAge, "maximum accepted witness age")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" || *bundlePath == "" || *trustRootPath == "" {
		fmt.Fprintln(stderr, "--file, --bundle, and --trust-root are required")
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
	mode := attest.ModeDefault
	if *strict {
		mode = attest.ModeStrict
	}
	result, verifyErr := attest.Verify(context.Background(), attest.VerifyRequest{
		Bundle:           bundle,
		Subjects:         []attest.Subject{subject},
		TrustRoot:        root,
		ExpectedIdentity: attest.IdentityPolicy{KeyID: *keyID, Issuer: *identityIssuer, Subject: *identitySubject},
		Mode:             mode,
		Now:              time.Now().UTC(),
		MaxWitnessAge:    *maxWitnessAge,
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

func writeFile(path string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, body, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
