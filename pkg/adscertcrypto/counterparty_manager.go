package adscertcrypto

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/glog"
)

type DNSResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

type fakeDnsResolver struct {
	fakeRecords []string
	fakeError   error
}

func (r *fakeDnsResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.fakeRecords, r.fakeError
}

type counterpartyMap map[string]*counterpartyInfo

type counterpartyInfo struct {
	registerableDomain  string
	currentPublicKey    x25519PublicKey
	currentSharedSecret x25519SharedSecret
	lastUpdateTime      time.Time
}

type counterpartyManager struct {
	counterparties atomic.Value // contains counterpartyMap instance
	mutex          sync.Mutex
	ticker         *time.Ticker
	cancel         context.CancelFunc
	wakeUp         chan struct{}

	myPrivateKey x25519PrivateKey

	dnsResolver DNSResolver
}

func NewCounterpartyManager(dnsResolver DNSResolver) *counterpartyManager {
	cm := &counterpartyManager{
		ticker:      time.NewTicker(30 * time.Second), // Make this configurable.
		wakeUp:      make(chan struct{}, 1),
		dnsResolver: dnsResolver,
	}

	// TODO: properly read in private key.
	cm.myPrivateKey.initialized = true

	cm.counterparties.Store(counterpartyMap{})
	cm.startAutoUpdate()
	return cm
}

func (cm *counterpartyManager) startAutoUpdate() {
	var ctx context.Context
	ctx, cm.cancel = context.WithCancel(context.Background())
	go func() {
		for {
			select {
			case <-ctx.Done():
				glog.Info("shutting down auto-update")
				return
			case <-cm.ticker.C:
				glog.Info("automatic wake-up")
			case <-cm.wakeUp:
				glog.Info("manual wake-up from wake-up signal")
			}
			cm.performUpdateSweep(ctx)
		}
	}()
}

func (cm *counterpartyManager) performUpdateSweep(ctx context.Context) {
	glog.Infof("Starting ads.cert update sweep")
	for domain := range cm.counterparties.Load().(counterpartyMap) {
		currentCounterpartyState := cm.lookup(domain)

		// Make this timing configurable
		if currentCounterpartyState.lastUpdateTime.Before(time.Now().Add(-300 * time.Second)) {
			glog.Infof("Trying to do an update for domain %s", domain)

			start := time.Now()

			records, err := cm.dnsResolver.LookupTXT(ctx, domain)
			if err != nil {
				glog.Warningf("Error looking up record for %s in %v: %v", domain, time.Now().Sub(start), err)
			} else {
				glog.Infof("Found text record for %s in %v: %v", domain, time.Now().Sub(start), records)

				// TODO: do this properly
				fixmeTextRecordConcat := []byte(strings.Join(records, ""))
				for i, b := range fixmeTextRecordConcat {
					if i >= 32 {
						break
					}
					currentCounterpartyState.currentPublicKey.publicKey[i] = b
				}
				currentCounterpartyState.currentPublicKey.initialized = true

				sharedSecret, err := calculateSharedSecret(cm.myPrivateKey, currentCounterpartyState.currentPublicKey)
				if err != nil {
					glog.Warningf("Error calculating shared secret for domain %s: %v", domain, err)
				} else {
					currentCounterpartyState.currentSharedSecret = sharedSecret
				}
			}

			currentCounterpartyState.lastUpdateTime = time.Now()
			cm.update(domain, currentCounterpartyState)
		} else {
			glog.Infof("skipping update for domain %s which is already up to date.", domain)
		}
	}
}

func (cm *counterpartyManager) StopAutoUpdate() {
	cm.ticker.Stop()
	cm.cancel()
}

func (cm *counterpartyManager) UpdateNow() {
	select {
	case cm.wakeUp <- struct{}{}:
		glog.Info("Wrote to wake-up channel.")
		// Channel publish succeeded.
	default:
		// Channel already has pending wake-up call.
		glog.Info("Didn't write to wake-up channel since there's a request pending")
	}
}

func (cm *counterpartyManager) lookup(registerableDomain string) counterpartyInfo {
	counterparty := cm.counterparties.Load().(counterpartyMap)[registerableDomain]

	if counterparty != nil {
		return *counterparty
	}

	return cm.register(registerableDomain)
}

func (cm *counterpartyManager) register(registerableDomain string) counterpartyInfo {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// We may encounter a race condition on registration, so check map again
	// after we acquire a lock.
	counterparty := cm.counterparties.Load().(counterpartyMap)[registerableDomain]
	if counterparty != nil {
		return *counterparty
	}

	counterparty = buildInitialCounterparty(registerableDomain)
	cm.unsafeStore(registerableDomain, counterparty)
	cm.UpdateNow()
	return *counterparty
}

func (cm *counterpartyManager) update(registerableDomain string, updatedCounterparty counterpartyInfo) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.unsafeStore(registerableDomain, &updatedCounterparty)
}

func (cm *counterpartyManager) unsafeStore(registerableDomain string, newCounterparty *counterpartyInfo) {
	currentMap := cm.counterparties.Load().(counterpartyMap)
	newMap := make(counterpartyMap)
	for k, v := range currentMap {
		newMap[k] = v
	}
	newMap[registerableDomain] = newCounterparty
	cm.counterparties.Store(newMap)
}

func buildInitialCounterparty(registerableDomain string) *counterpartyInfo {
	return &counterpartyInfo{
		registerableDomain: registerableDomain,
	}
}

// Counterparty represents a peer organization within the programmatic
// advertising ecosystem who may or may not participate within the ads.cert
// standard. A Counterparty safely encapsulates the public key material used for
// authenticating with the entity.
type Counterparty interface {
	GetAdsCertIdentityDomain() string

	HasSharedSecret() bool

	SharedSecret() *[32]byte

	KeyID() string

	Status() string
}

type CounterpartyManager interface {
	FindCounterpartiesByInvocationHostname(hostname string) ([]Counterparty, error)

	FindCounterpartyByCallsign(callsign string) (Counterparty, error)
}
