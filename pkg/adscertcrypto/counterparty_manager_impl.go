package adscertcrypto

type counterpartyManager struct {
}

func (cm *counterpartyManager) FindCounterpartiesByInvocationHostname(hostname string) ([]Counterparty, error) {
	return []Counterparty{}, nil
}

func (cm *counterpartyManager) FindCounterpartyByCallsign(callsign string) (Counterparty, error) {
	return nil, nil
}
