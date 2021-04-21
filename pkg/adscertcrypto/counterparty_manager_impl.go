package adscertcrypto

type counterparty struct {
	sharedSecret [32]byte
}

func (c *counterparty) GetAdsCertIdentityDomain() string {
	return "example.com"
}

// TODO: enumeration of counterparty capabilities

func (c *counterparty) HasSharedSecret() bool {
	return false
}

// TODO: change this
func (c *counterparty) SharedSecret() *[32]byte {

	// TODO: clean this up
	return &c.sharedSecret
}

func (c *counterparty) KeyID() string {
	return "a1b2c3"
}

func (c *counterparty) Status() string {
	return "UNKNOWN"
}

type counterpartyManager struct {
}

func (cm *counterpartyManager) FindCounterpartiesByInvocationHostname(hostname string) ([]Counterparty, error) {
	counterparty := &counterparty{}

	return []Counterparty{counterparty}, nil
}

func (cm *counterpartyManager) FindCounterpartyByCallsign(callsign string) (Counterparty, error) {
	return &counterparty{}, nil
}
