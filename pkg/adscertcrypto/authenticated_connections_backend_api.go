package adscertcrypto

type RequestInfo struct {
	InvocationHostname string
	URLHash            [32]byte
	BodyHash           [32]byte
}

type AuthenticatedConnectionSigningPackage struct {
	Timestamp string
	Nonce     string

	RequestInfo RequestInfo
}

type AuthenticatedConnectionSignatureResponse struct {
	SignatureMessages []string
}

type AuthenticatedConnectionVerificationPackage struct {
	RequestInfo      RequestInfo
	SignatureMessage string
}

type AuthenticatedConnectionVerificationResponse struct {
	BodyValid bool
	URLValid  bool

	// Curtis notes:
	// See the comments on AuthenticatedConnectionVerification for requirements about what this
	// API needs to return.
}
