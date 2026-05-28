package attest

import (
	"fmt"
	"strings"
)

func validatePredicateSemantics(predicate Predicate) error {
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
