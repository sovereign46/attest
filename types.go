package attest

import "time"

const (
	SchemaVersion              = 1
	BundleMediaType            = "application/vnd.s46.attestation.bundle.v1+json"
	InTotoPayloadType          = "application/vnd.in-toto+json"
	InTotoStatementType        = "https://in-toto.io/Statement/v1"
	S46PredicateType           = "https://sovereign46.dev/attestation/v1"
	SignatureAlgorithm         = "ed25519"
	DigestAlgorithmSHA256      = "sha256"
	DefaultWitnessMaxAge       = 24 * time.Hour
	DefaultSignatureFutureSkew = 5 * time.Minute
	DefaultSubjectFileName     = "artifact"
	MaxStatementSubjects       = 1024
	MaxSubjectDigests          = 32
)

type State string

const (
	StateTrusted State = "trusted"
	StateWarning State = "warning"
	StateRefused State = "refused"
)

type Mode string

const (
	ModeDefault Mode = "default"
	ModeStrict  Mode = "strict"
)

type TransparencyState string

const (
	TransparencyOperational TransparencyState = "operational"
	TransparencyDegraded    TransparencyState = "degraded"
	TransparencyOffline     TransparencyState = "offline"
	TransparencyCompromised TransparencyState = "compromised"
)

type KeyPair struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

type Identity struct {
	Issuer  string `json:"issuer,omitempty"`
	Subject string `json:"subject,omitempty"`
}

type IdentityPolicy struct {
	KeyID   string `json:"keyId,omitempty"`
	Issuer  string `json:"issuer,omitempty"`
	Subject string `json:"subject,omitempty"`
}

type Subject struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
	Path      string `json:"-"`
}

type Bundle struct {
	Schema    int          `json:"schema"`
	MediaType string       `json:"mediaType"`
	Envelope  DSSEEnvelope `json:"dsseEnvelope"`
	Sigsum    *SigsumProof `json:"sigsumTransparency,omitempty"`
}

type DSSEEnvelope struct {
	PayloadType string              `json:"payloadType"`
	Payload     string              `json:"payload"`
	Signatures  []EnvelopeSignature `json:"signatures"`
}

type EnvelopeSignature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

type Statement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     Predicate            `json:"predicate"`
}

type ResourceDescriptor struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
	Size   int64             `json:"size,omitempty"`
}

type Predicate struct {
	BuildType string    `json:"buildType"`
	SignedAt  time.Time `json:"signedAt"`
	Signer    Signer    `json:"signer"`
}

type Signer struct {
	KeyID     string   `json:"keyId"`
	Algorithm string   `json:"algorithm"`
	Identity  Identity `json:"identity,omitempty"`
}

type TrustRoot struct {
	Schema              int                  `json:"schema"`
	SigningKeys         []TrustedKey         `json:"signingKeys"`
	Sigsum              SigsumTrustRoot      `json:"sigsum,omitempty"`
	TransparencyStatus  TransparencyStatus   `json:"transparencyStatus,omitempty"`
	IdentityRevocations []IdentityRevocation `json:"identityRevocations,omitempty"`
}

type TrustedKey struct {
	KeyID     string   `json:"keyId"`
	PublicKey string   `json:"publicKey"`
	URL       string   `json:"url,omitempty"`
	Identity  Identity `json:"identity,omitempty"`
}

type SigsumTrustRoot struct {
	PolicyName string       `json:"policyName,omitempty"`
	Policy     string       `json:"policy,omitempty"`
	Logs       []TrustedKey `json:"logs,omitempty"`
	Witnesses  []TrustedKey `json:"witnesses,omitempty"`
	Quorum     int          `json:"quorum,omitempty"`
}

type TransparencyStatus struct {
	State  TransparencyState `json:"state,omitempty"`
	Reason string            `json:"reason,omitempty"`
	Since  time.Time         `json:"since,omitempty"`
}

type IdentityRevocation struct {
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	RevokedSince time.Time `json:"revokedSince"`
	Reason       string    `json:"reason,omitempty"`
}

type SigsumProof struct {
	Proof string `json:"proof"`
}

type SignOptions struct {
	Subjects   []Subject
	PrivateKey string
	KeyID      string
	Identity   Identity
	SignedAt   time.Time
	Sigsum     *SigsumSignOptions
}

type SigsumSignOptions struct {
	// Live Sigsum submission. Set PolicyName or Policy to submit to a real log.
	PolicyName          string
	Policy              string
	RateLimitDomain     string
	RateLimitPrivateKey string
	Timeout             time.Duration
	RequestTimeout      time.Duration
	PollDelay           time.Duration
	UserAgent           string

	// Local deterministic proof generation for tests/development.
	LogPrivateKey          string
	WitnessPrivateKeys     []string
	WitnessTimestamp       time.Time
	DeterministicTreeNonce string
}

type VerifyRequest struct {
	Bundle           Bundle
	Subjects         []Subject
	TrustRoot        TrustRoot
	ExpectedIdentity IdentityPolicy
	Mode             Mode
	Now              time.Time
	MaxWitnessAge    time.Duration
}

type VerifyResult struct {
	State           State              `json:"state"`
	Diagnostics     []Diagnostic       `json:"diagnostics,omitempty"`
	Signature       SignatureResult    `json:"signature"`
	Attestation     AttestationResult  `json:"attestation"`
	Transparency    TransparencyResult `json:"transparency"`
	TrustStatus     TrustStatusResult  `json:"trustStatus"`
	SignatureTime   time.Time          `json:"signatureTime,omitempty"`
	SigningKeyID    string             `json:"signingKeyId,omitempty"`
	SigningIdentity Identity           `json:"signingIdentity,omitempty"`
}

type Diagnostic struct {
	Code     string `json:"code"`
	Severity State  `json:"severity"`
	Message  string `json:"message"`
}

type SignatureResult struct {
	Valid     bool   `json:"valid"`
	Algorithm string `json:"algorithm,omitempty"`
	KeyID     string `json:"keyId,omitempty"`
}

type AttestationResult struct {
	Valid    bool      `json:"valid"`
	Subjects []Subject `json:"subjects,omitempty"`
}

type TransparencyResult struct {
	Valid              bool      `json:"valid"`
	Present            bool      `json:"present"`
	VerifiedWitnesses  int       `json:"verifiedWitnesses"`
	Quorum             int       `json:"quorum,omitempty"`
	QuorumPolicy       string    `json:"quorumPolicy,omitempty"`
	LogKeyID           string    `json:"logKeyId,omitempty"`
	WitnessedAt        time.Time `json:"witnessedAt,omitempty"`
	Stale              bool      `json:"stale,omitempty"`
	VerificationDetail string    `json:"verificationDetail,omitempty"`
}

type TrustStatusResult struct {
	State  TransparencyState `json:"state,omitempty"`
	Reason string            `json:"reason,omitempty"`
	Since  time.Time         `json:"since,omitempty"`
}

type SubjectFileOptions struct {
	Path        string
	Name        string
	RequireGGUF bool
}
