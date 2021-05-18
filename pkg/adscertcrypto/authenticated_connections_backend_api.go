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
	// TODO: provide more details on verification
	BodyValid bool
	URLValid  bool
}
