package attest

import (
	"bufio"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	maxSecurityStringBytes   = 4096
	maxSigsumPolicyBytes     = 1 << 20
	maxSigsumPolicyLineBytes = bufio.MaxScanTokenSize - 1
	maxSigsumPolicyEntities  = maxJSONCollectionItems
	maxSigsumPolicyDepth     = maxJSONDepth
	maxSigsumProofBytes      = 4 << 20
	maxSigsumProofLines      = maxJSONCollectionItems + 128
)

func validateBundleResourceBounds(bundle Bundle) error {
	if err := validateBoundedStrings(maxSecurityStringBytes, "bundle media or payload type", bundle.MediaType, bundle.Envelope.PayloadType); err != nil {
		return err
	}
	if err := validateBoundedString(bundle.Envelope.Payload, maxJSONBytes, "bundle payload encoding"); err != nil {
		return err
	}
	if len(bundle.Envelope.Signatures) > maxJSONCollectionItems {
		return fmt.Errorf("bundle signatures exceed %d-item limit", maxJSONCollectionItems)
	}
	for i, signature := range bundle.Envelope.Signatures {
		if err := validateBoundedStrings(maxSecurityStringBytes, fmt.Sprintf("bundle signature[%d]", i), signature.KeyID, signature.Sig); err != nil {
			return err
		}
	}
	if bundle.Sigsum != nil {
		if err := validateSigsumProofResourceBounds(bundle.Sigsum.Proof); err != nil {
			return err
		}
	}
	return validateBundleEncodedSize(bundle)
}

func validateTrustRootOptionsResourceBounds(options TrustRootOptions) error {
	return validateTrustRootResourceBounds(TrustRoot{
		Schema:                 SchemaVersion,
		SigningKeys:            options.SigningKeys,
		Sigsum:                 SigsumTrustRoot{PolicyName: options.SigsumPolicyName, Policy: options.SigsumPolicy, SubmitKeys: options.SigsumSubmitKeys},
		TransparencyStatus:     options.TransparencyStatus,
		Expires:                options.Expires,
		RequireSigningIdentity: options.RequireSigningIdentity,
	})
}

func validateTrustRootResourceBounds(root TrustRoot) error {
	if len(root.SigningKeys) > maxJSONCollectionItems {
		return fmt.Errorf("signingKeys exceeds %d-item limit", maxJSONCollectionItems)
	}
	for i, key := range root.SigningKeys {
		if err := validateTrustedKeyResourceBounds(key, fmt.Sprintf("signingKeys[%d]", i)); err != nil {
			return err
		}
	}
	if err := validateSigsumTrustRootResourceBounds(root.Sigsum); err != nil {
		return err
	}
	if err := validateBoundedStrings(maxSecurityStringBytes, "transparencyStatus", string(root.TransparencyStatus.State), root.TransparencyStatus.Reason); err != nil {
		return err
	}
	if len(root.IdentityRevocations) > maxJSONCollectionItems {
		return fmt.Errorf("identityRevocations exceeds %d-item limit", maxJSONCollectionItems)
	}
	for i, revocation := range root.IdentityRevocations {
		if err := validateBoundedStrings(maxSecurityStringBytes, fmt.Sprintf("identityRevocations[%d]", i), revocation.Issuer, revocation.Subject, revocation.Reason); err != nil {
			return err
		}
	}
	return validateTrustRootEncodedSize(root)
}

func validateSigsumTrustRootResourceBounds(root SigsumTrustRoot) error {
	for label, count := range map[string]int{
		"sigsum.logs":       len(root.Logs),
		"sigsum.witnesses":  len(root.Witnesses),
		"sigsum.submitKeys": len(root.SubmitKeys),
	} {
		if count > maxJSONCollectionItems {
			return fmt.Errorf("%s exceeds %d-item limit", label, maxJSONCollectionItems)
		}
	}
	for i, key := range root.Logs {
		if err := validateTrustedKeyResourceBounds(key, fmt.Sprintf("sigsum.logs[%d]", i)); err != nil {
			return err
		}
	}
	for i, key := range root.Witnesses {
		if err := validateTrustedKeyResourceBounds(key, fmt.Sprintf("sigsum.witnesses[%d]", i)); err != nil {
			return err
		}
	}
	for i, key := range root.SubmitKeys {
		if err := validateBoundedStrings(maxSecurityStringBytes, fmt.Sprintf("sigsum.submitKeys[%d]", i), key.KeyID, key.PublicKey, key.SigningKeyID, key.Identity.Issuer, key.Identity.Subject); err != nil {
			return err
		}
	}
	if err := validateBoundedString(root.PolicyName, maxSecurityStringBytes, "sigsum.policyName"); err != nil {
		return err
	}
	return validateSigsumPolicyComplexity(root.Policy)
}

func validateSigsumSignOptionsResourceBounds(options SigsumSignOptions) error {
	if err := validateBoundedStrings(maxSecurityStringBytes, "Sigsum option", options.SubmitPrivateKey, options.LogPrivateKey,
		options.RateLimitPrivateKey, options.PolicyName, options.RateLimitDomain,
		options.UserAgent, options.DeterministicTreeNonce); err != nil {
		return err
	}
	if len(options.WitnessPrivateKeys) > maxJSONCollectionItems {
		return fmt.Errorf("Sigsum witnesses exceed %d-item limit", maxJSONCollectionItems)
	}
	for _, key := range options.WitnessPrivateKeys {
		if err := validateBoundedString(key, maxSecurityStringBytes, "Sigsum witness key"); err != nil {
			return err
		}
	}
	return validateSigsumPolicyComplexity(options.Policy)
}

func validateStatementResourceBounds(statement Statement) error {
	if err := validateBoundedStrings(maxSecurityStringBytes, "statement type", statement.Type, statement.PredicateType); err != nil {
		return err
	}
	if len(statement.Subject) > MaxStatementSubjects {
		return fmt.Errorf("statement contains too many subjects: %d > %d", len(statement.Subject), MaxStatementSubjects)
	}
	for i, subject := range statement.Subject {
		if err := validateBoundedString(subject.Name, maxSecurityStringBytes, fmt.Sprintf("statement subject[%d].name", i)); err != nil {
			return err
		}
		if len(subject.Digest) > MaxSubjectDigests {
			return fmt.Errorf("statement subject[%d] contains too many digests: %d > %d", i, len(subject.Digest), MaxSubjectDigests)
		}
		for algorithm, digest := range subject.Digest {
			if err := validateBoundedStrings(maxSecurityStringBytes, fmt.Sprintf("statement subject[%d] digest", i), algorithm, digest); err != nil {
				return err
			}
		}
	}
	if err := validatePredicateSemantics(statement.Predicate); err != nil {
		return err
	}
	_, err := statementJSONSizeUpperBound(statement)
	return err
}

func statementJSONSizeUpperBound(statement Statement) (int, error) {
	// Static allowances cover all compact-JSON punctuation, field names,
	// integers, timestamps, and collection separators; strings are exact.
	budget := newJSONSizeBudget("statement")
	if err := budget.addBytes(2048 + len(statement.Subject)*128); err != nil {
		return 0, err
	}
	for _, value := range []string{statement.Type, statement.PredicateType} {
		if err := budget.addString(value); err != nil {
			return 0, err
		}
	}
	for _, subject := range statement.Subject {
		if err := budget.addString(subject.Name); err != nil {
			return 0, err
		}
		for algorithm, digest := range subject.Digest {
			if err := budget.addBytes(32); err != nil {
				return 0, err
			}
			if err := budget.addString(algorithm); err != nil {
				return 0, err
			}
			if err := budget.addString(digest); err != nil {
				return 0, err
			}
		}
	}
	if err := addPredicateStringsToBudget(budget, statement.Predicate); err != nil {
		return 0, err
	}
	return budget.used(), nil
}

func addPredicateStringsToBudget(budget *jsonSizeBudget, predicate Predicate) error {
	values := []string{
		predicate.BuildType,
		string(predicate.Kind),
		predicate.Signer.KeyID,
		predicate.Signer.Algorithm,
		predicate.Signer.Identity.Issuer,
		predicate.Signer.Identity.Subject,
	}
	if predicate.Release != nil {
		values = append(values, predicate.Release.Channel)
	}
	if predicate.Advisory != nil {
		values = append(values, predicate.Advisory.ID, predicate.Advisory.Severity, predicate.Advisory.Summary, predicate.Advisory.URL)
	}
	if predicate.Yank != nil {
		if err := budget.addBytes(len(predicate.Yank.ReplacedBy) * 8); err != nil {
			return err
		}
		values = append(values, predicate.Yank.Reason)
		values = append(values, predicate.Yank.ReplacedBy...)
	}
	for _, value := range values {
		if err := budget.addString(value); err != nil {
			return err
		}
	}
	return nil
}

func validateBundleEncodedSize(bundle Bundle) error {
	_, err := bundleJSONSizeUpperBound(bundle)
	return err
}

func bundleJSONSizeUpperBound(bundle Bundle) (int, error) {
	// Static allowances include MarshalIndent whitespace and the trailing newline
	// added by MarshalBundle; strings are counted at their exact encoded size.
	budget := newJSONSizeBudget("bundle")
	if err := budget.addBytes(1024 + len(bundle.Envelope.Signatures)*64); err != nil {
		return 0, err
	}
	for _, value := range []string{bundle.MediaType, bundle.Envelope.PayloadType, bundle.Envelope.Payload} {
		if err := budget.addString(value); err != nil {
			return 0, err
		}
	}
	for _, signature := range bundle.Envelope.Signatures {
		if err := budget.addString(signature.KeyID); err != nil {
			return 0, err
		}
		if err := budget.addString(signature.Sig); err != nil {
			return 0, err
		}
	}
	if bundle.Sigsum != nil {
		if err := budget.addString(bundle.Sigsum.Proof); err != nil {
			return 0, err
		}
	}
	return budget.used(), nil
}

func validateTrustRootEncodedSize(root TrustRoot) error {
	_, err := trustRootJSONSizeUpperBound(root)
	return err
}

func trustRootJSONSizeUpperBound(root TrustRoot) (int, error) {
	// Static allowances include MarshalIndent whitespace, timestamps, integers,
	// field names, punctuation, and MarshalTrustRoot's trailing newline.
	budget := newJSONSizeBudget("trust root")
	overhead := 4096 +
		(len(root.SigningKeys)+len(root.Sigsum.Logs)+len(root.Sigsum.Witnesses))*256 +
		len(root.Sigsum.SubmitKeys)*256 + len(root.IdentityRevocations)*256
	if err := budget.addBytes(overhead); err != nil {
		return 0, err
	}
	for _, keys := range [][]TrustedKey{root.SigningKeys, root.Sigsum.Logs, root.Sigsum.Witnesses} {
		for _, key := range keys {
			for _, value := range []string{key.KeyID, key.PublicKey, key.URL, key.Identity.Issuer, key.Identity.Subject} {
				if err := budget.addString(value); err != nil {
					return 0, err
				}
			}
		}
	}
	for _, key := range root.Sigsum.SubmitKeys {
		for _, value := range []string{key.KeyID, key.PublicKey, key.SigningKeyID, key.Identity.Issuer, key.Identity.Subject} {
			if err := budget.addString(value); err != nil {
				return 0, err
			}
		}
	}
	for _, value := range []string{root.Sigsum.PolicyName, root.Sigsum.Policy, string(root.TransparencyStatus.State), root.TransparencyStatus.Reason} {
		if err := budget.addString(value); err != nil {
			return 0, err
		}
	}
	for _, revocation := range root.IdentityRevocations {
		for _, value := range []string{revocation.Issuer, revocation.Subject, revocation.Reason} {
			if err := budget.addString(value); err != nil {
				return 0, err
			}
		}
	}
	return budget.used(), nil
}

func validateTrustedKeyResourceBounds(key TrustedKey, label string) error {
	return validateBoundedStrings(maxSecurityStringBytes, label, key.KeyID, key.PublicKey, key.URL, key.Identity.Issuer, key.Identity.Subject)
}

func validateBoundedStrings(limit int, label string, values ...string) error {
	for _, value := range values {
		if err := validateBoundedString(value, limit, label); err != nil {
			return err
		}
	}
	return nil
}

func validateBoundedString(value string, limit int, label string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s contains invalid UTF-8", label)
	}
	if len(value) > limit {
		return fmt.Errorf("%s exceeds %d-byte limit", label, limit)
	}
	return nil
}

type jsonSizeBudget struct {
	label     string
	remaining int
}

func newJSONSizeBudget(label string) *jsonSizeBudget {
	return &jsonSizeBudget{label: label, remaining: maxJSONBytes}
}

func (b *jsonSizeBudget) used() int {
	return maxJSONBytes - b.remaining
}

func (b *jsonSizeBudget) addBytes(size int) error {
	if size < 0 || size > b.remaining {
		return fmt.Errorf("%s JSON exceeds %d-byte limit", b.label, maxJSONBytes)
	}
	b.remaining -= size
	return nil
}

func (b *jsonSizeBudget) addString(value string) error {
	size, err := encodedJSONStringSize(value)
	if err != nil {
		return err
	}
	return b.addBytes(size)
}

func encodedJSONStringSize(value string) (int, error) {
	if !utf8.ValidString(value) {
		return 0, fmt.Errorf("JSON string contains invalid UTF-8")
	}
	size := 2
	for index := 0; index < len(value); {
		character := value[index]
		if character < utf8.RuneSelf {
			switch character {
			case '\\', '"', '\b', '\f', '\n', '\r', '\t':
				size += 2
			case '<', '>', '&':
				size += 6
			default:
				if character < 0x20 {
					size += 6
				} else {
					size++
				}
			}
			index++
			continue
		}
		r, width := utf8.DecodeRuneInString(value[index:])
		if r == '\u2028' || r == '\u2029' {
			size += 6
		} else {
			size += width
		}
		index += width
	}
	return size, nil
}

func validateSigsumPolicyComplexity(text string) error {
	if err := validateBoundedString(text, maxSigsumPolicyBytes, "sigsum policy"); err != nil {
		return err
	}
	if strings.TrimSpace(text) == "" {
		return nil
	}
	depths := map[string]int{"none": 1}
	entities := 0
	references := 0
	for _, line := range strings.Split(text, "\n") {
		if len(line) > maxSigsumPolicyLineBytes {
			return fmt.Errorf("sigsum policy line exceeds %d-byte limit", maxSigsumPolicyLineBytes)
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		entities++
		if entities > maxSigsumPolicyEntities {
			return fmt.Errorf("sigsum policy exceeds %d-entity limit", maxSigsumPolicyEntities)
		}
		switch fields[0] {
		case "witness":
			if len(fields) >= 2 {
				depths[fields[1]] = 1
			}
		case "group":
			if len(fields) < 4 {
				continue
			}
			references += len(fields) - 3
			if references > maxSigsumPolicyEntities {
				return fmt.Errorf("sigsum policy exceeds %d-member limit", maxSigsumPolicyEntities)
			}
			depth := 1
			for _, member := range fields[3:] {
				if memberDepth := depths[member] + 1; memberDepth > depth {
					depth = memberDepth
				}
			}
			if depth > maxSigsumPolicyDepth {
				return fmt.Errorf("sigsum policy nesting exceeds %d", maxSigsumPolicyDepth)
			}
			depths[fields[1]] = depth
		}
	}
	return nil
}

func validateSigsumProofResourceBounds(proof string) error {
	if err := validateBoundedString(proof, maxSigsumProofBytes, "Sigsum proof"); err != nil {
		return err
	}
	lines := 0
	cosignatures := 0
	for start := 0; start <= len(proof); {
		lines++
		if lines > maxSigsumProofLines {
			return fmt.Errorf("Sigsum proof exceeds %d-line limit", maxSigsumProofLines)
		}
		end := strings.IndexByte(proof[start:], '\n')
		if end < 0 {
			end = len(proof) - start
		}
		if strings.HasPrefix(proof[start:start+end], "cosignature=") {
			cosignatures++
			if cosignatures > maxJSONCollectionItems {
				return fmt.Errorf("Sigsum proof exceeds %d-cosignature limit", maxJSONCollectionItems)
			}
		}
		start += end + 1
		if start > len(proof) {
			break
		}
	}
	return nil
}
