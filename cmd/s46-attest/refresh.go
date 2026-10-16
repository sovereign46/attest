package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	attest "github.com/sovereign46/attest"
)

func runRefresh(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("refresh", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "original subject file (arbitrary bytes, including registry JSON)")
	name := fs.String("subject-name", "", "signed subject name; defaults to file basename")
	bundlePath := fs.String("bundle", "", "existing bundle path")
	out := fs.String("out", "", "verified bundle output path (may equal --bundle)")
	rootPath := fs.String("trust-root", "", "pinned trust root JSON path")
	keyID := fs.String("key-id", "", "required expected signing key ID")
	issuer := fs.String("identity-issuer", "", "required expected identity issuer")
	subject := fs.String("identity-subject", "", "required expected identity subject")
	kindRaw := fs.String("predicate-kind", string(attest.PredicateKindRelease), "expected predicate: release, advisory, or yank")
	submitKeyPath := fs.String("sigsum-submit-private-key-file", "", "authorized separate Sigsum submit private key file")
	policyName := fs.String("sigsum-policy", "", "named policy; resolved text must match embedded trust-root policy")
	policyPath := fs.String("sigsum-policy-file", "", "policy file; text must match embedded trust-root policy")
	tokenDomain := fs.String("sigsum-token-domain", "", "Sigsum submit-token rate-limit domain")
	tokenKeyPath := fs.String("sigsum-token-private-key-file", "", "Sigsum submit-token private key file")
	timeout := fs.Duration("sigsum-timeout", attest.RefreshTimeoutLimit, "total submission timeout (at most 10m)")
	requestTimeout := fs.Duration("sigsum-request-timeout", attest.RefreshRequestTimeoutLimit, "per-request timeout (at most 30s)")
	pollDelay := fs.Duration("sigsum-poll-delay", 2*time.Second, "Sigsum polling delay")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *file == "" || *bundlePath == "" || *out == "" || *rootPath == "" || *keyID == "" || *issuer == "" || *subject == "" || *submitKeyPath == "" || (*policyName == "") == (*policyPath == "") {
		fmt.Fprintln(stderr, "refresh requires --file, --bundle, --out, --trust-root, --key-id, --identity-issuer, --identity-subject, --sigsum-submit-private-key-file and exactly one of --sigsum-policy or --sigsum-policy-file")
		return 2
	}
	kind, ok := parsePredicateKind(*kindRaw)
	if !ok {
		fmt.Fprintf(stderr, "unsupported --predicate-kind %q\n", *kindRaw)
		return 2
	}
	if *name == "" {
		*name = filepath.Base(*file)
	}
	expectedSubject, err := attest.SubjectFromFile(attest.SubjectFileOptions{Path: *file, Name: *name})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	bundle, err := attest.LoadBundle(*bundlePath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	root, err := attest.LoadTrustRoot(*rootPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	submitKey, err := attest.ReadPrivateKeyFile(*submitKeyPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	options := attest.SigsumSignOptions{SubmitPrivateKey: submitKey, PolicyName: *policyName, RateLimitDomain: *tokenDomain, Timeout: *timeout, RequestTimeout: *requestTimeout, PollDelay: *pollDelay}
	if *policyPath != "" {
		options.Policy, err = readTrimmedFile(*policyPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if *tokenKeyPath != "" {
		options.RateLimitPrivateKey, err = attest.ReadPrivateKeyFile(*tokenKeyPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	refreshed, err := attest.RefreshTransparency(ctx, attest.VerifyRequest{
		Bundle: bundle, Subjects: []attest.Subject{expectedSubject}, TrustRoot: root,
		ExpectedIdentity:      attest.IdentityPolicy{KeyID: *keyID, Issuer: *issuer, Subject: *subject},
		ExpectedPredicateKind: kind,
	}, options)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := attest.WriteBundle(*out, refreshed); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s\n", *out)
	return 0
}
