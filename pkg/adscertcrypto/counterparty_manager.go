package adscertcrypto

// Counterparty represents a peer organization within the programmatic
// advertising ecosystem who may or may not participate within the ads.cert
// standard. A Counterparty safely encapsulates the public key material used for
// authenticating with the entity.
type Counterparty interface {
	GetAdsCertIdentityDomain() string
	// TODO: enumeration of counterparty capabilities

	HasSharedSecret() bool
	// TODO: change this
	SharedSecret() *[32]byte

	KeyID() string

	Status() string
}

type CounterpartyManager interface {
	FindCounterpartiesByInvocationHostname(hostname string) ([]Counterparty, error)

	FindCounterpartyByCallsign(callsign string) (Counterparty, error)
}

func NewCounterpartyManager() CounterpartyManager {
	return &counterpartyManager{}
}
