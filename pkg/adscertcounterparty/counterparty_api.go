package adscertcounterparty

type CounterpartyStatus int

const (
	StatusUnspecified CounterpartyStatus = iota
	StatusOK
	StatusNotYetChecked
	StatusErrorOnDNS
	StatusErrorOnDNSSEC
	StatusErrorOnAdsCertConfigParse
	StatusErrorOnAdsCertConfigEval
	StatusErrorOnKeyValidation
	StatusErrorOnSharedSecretCalculation
)

type CounterpartyAPI interface {
	LookUpInvocationCounterpartyByHostname(invocationHostname string) (InvocationCounterparty, error)

	LookUpSignatureCounterpartyByCallsign(adsCertCallsign string) (SignatureCounterparty, error)
}

type InvocationCounterparty interface {
	GetStatus() CounterpartyStatus

	GetSignatureCounterparties() []SignatureCounterparty
}

type SignatureCounterparty interface {
	GetAdsCertIdentityDomain() string

	HasSharedSecret() bool

	SharedSecret() *[32]byte

	KeyID() string

	GetStatus() CounterpartyStatus
}
