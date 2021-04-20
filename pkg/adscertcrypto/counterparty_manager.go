package adscertcrypto

type CounterpartyManager interface {
	FindCounterpartiesByInvocationHostname(hostname string) ([]Counterparty, error)

	FindCounterpartyByCallsign(callsign string) (Counterparty, error)	
}