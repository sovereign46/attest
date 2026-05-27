package attest

import "context"

func VerifyBytes(ctx context.Context, bundleBytes []byte, req VerifyRequest) (VerifyResult, error) {
	bundle, err := ParseBundle(bundleBytes)
	if err != nil {
		return VerifyResult{State: StateRefused, Diagnostics: []Diagnostic{{Code: "bundle-invalid", Severity: StateRefused, Message: err.Error()}}}, err
	}
	req.Bundle = bundle
	return Verify(ctx, req)
}

func SignFile(ctx context.Context, file SubjectFileOptions, options SignOptions) (Bundle, error) {
	subject, err := SubjectFromFile(file)
	if err != nil {
		return Bundle{}, err
	}
	options.Subjects = []Subject{subject}
	return Sign(ctx, options)
}
