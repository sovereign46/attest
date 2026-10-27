package attest

import (
	"fmt"
	"strings"
)

func validatePredicateSemantics(predicate Predicate) error {
	if err := validateBoundedStrings(maxSecurityStringBytes, "predicate identity field",
		predicate.BuildType, string(predicate.Kind), predicate.Signer.KeyID,
		predicate.Signer.Algorithm, predicate.Signer.Identity.Issuer,
		predicate.Signer.Identity.Subject); err != nil {
		return err
	}
	if predicate.Release != nil {
		if err := validateBoundedString(predicate.Release.Channel, maxSecurityStringBytes, "release channel"); err != nil {
			return err
		}
	}
	if predicate.Advisory != nil {
		if err := validateBoundedStrings(maxSecurityStringBytes, "advisory field", predicate.Advisory.ID,
			predicate.Advisory.Severity, predicate.Advisory.Summary, predicate.Advisory.URL); err != nil {
			return err
		}
	}
	if predicate.Yank != nil {
		if len(predicate.Yank.ReplacedBy) > maxJSONCollectionItems {
			return fmt.Errorf("yank replacements exceed %d-item limit", maxJSONCollectionItems)
		}
		if err := validateBoundedString(predicate.Yank.Reason, maxSecurityStringBytes, "yank reason"); err != nil {
			return err
		}
		for _, replacement := range predicate.Yank.ReplacedBy {
			if err := validateBoundedString(replacement, maxSecurityStringBytes, "yank replacement"); err != nil {
				return err
			}
		}
	}
	if predicate.Kind == "" {
		return fmt.Errorf("predicate kind is required")
	}
	expectedBuildType := buildTypeForPredicateKind(predicate.Kind)
	if expectedBuildType == "" {
		return fmt.Errorf("unsupported predicate kind %q", predicate.Kind)
	}
	if predicate.BuildType != expectedBuildType {
		return fmt.Errorf("predicate buildType %q does not match kind %q", predicate.BuildType, predicate.Kind)
	}
	switch predicate.Kind {
	case PredicateKindRelease:
		if predicate.Release == nil {
			return fmt.Errorf("release predicate details are required")
		}
		if predicate.Advisory != nil || predicate.Yank != nil {
			return fmt.Errorf("release predicate must not include advisory or yank details")
		}
	case PredicateKindAdvisory:
		if predicate.Advisory == nil {
			return fmt.Errorf("advisory predicate details are required")
		}
		if predicate.Release != nil || predicate.Yank != nil {
			return fmt.Errorf("advisory predicate must not include release or yank details")
		}
		if strings.TrimSpace(predicate.Advisory.ID) == "" {
			return fmt.Errorf("advisory id is required")
		}
		if strings.TrimSpace(predicate.Advisory.Summary) == "" {
			return fmt.Errorf("advisory summary is required")
		}
	case PredicateKindYank:
		if predicate.Yank == nil {
			return fmt.Errorf("yank predicate details are required")
		}
		if predicate.Release != nil || predicate.Advisory != nil {
			return fmt.Errorf("yank predicate must not include release or advisory details")
		}
		if strings.TrimSpace(predicate.Yank.Reason) == "" {
			return fmt.Errorf("yank reason is required")
		}
	}
	return nil
}

func buildTypeForPredicateKind(kind PredicateKind) string {
	switch kind {
	case PredicateKindRelease:
		return S46ReleaseBuildType
	case PredicateKindAdvisory:
		return S46AdvisoryBuildType
	case PredicateKindYank:
		return S46YankBuildType
	default:
		return ""
	}
}
