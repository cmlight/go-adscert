package adscertcrypto

type counterparty struct {
	// sharedSecret [32]byte
	counterpartyInfo counterpartyInfo
}

func (c *counterparty) GetAdsCertIdentityDomain() string {
	return c.counterpartyInfo.registerableDomain
}

// TODO: enumeration of counterparty capabilities

func (c *counterparty) HasSharedSecret() bool {
	return c.counterpartyInfo.currentSharedSecret.initialized
}

// TODO: change this
func (c *counterparty) SharedSecret() *[32]byte {

	// TODO: clean this up
	return &c.counterpartyInfo.currentSharedSecret.sharedSecret
}

func (c *counterparty) KeyID() string {
	return "a1b2c3"
}

func (c *counterparty) Status() string {
	return "TODO"
}

func (cm *counterpartyManager) FindCounterpartiesByInvocationHostname(hostname string) ([]Counterparty, error) {
	counterparty := &counterparty{counterpartyInfo: cm.lookup(hostname)}

	return []Counterparty{counterparty}, nil
}

func (cm *counterpartyManager) FindCounterpartyByCallsign(callsign string) (Counterparty, error) {
	return &counterparty{}, nil
}
