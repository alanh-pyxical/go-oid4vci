package issuer

import (
	"context"
	"fmt"
	"sync"
	"time"

	oid4vci "github.com/alanh-pyxical/go-oid4vci"
)

// MemoryOfferStore is a thread-safe in-memory [OfferStore]. It is suitable
// for tests and single-process deployments. For production use, replace it
// with a persistent implementation backed by your database of choice.
type MemoryOfferStore struct {
	mu     sync.Mutex
	offers map[string]*offerEntry // keyed by pre-authorised code
}

type offerEntry struct {
	offer *Offer
	used  bool
}

// NewMemoryOfferStore creates a MemoryOfferStore.
func NewMemoryOfferStore() *MemoryOfferStore {
	return &MemoryOfferStore{offers: make(map[string]*offerEntry)}
}

// Save implements [OfferStore].
func (s *MemoryOfferStore) Save(_ context.Context, offer *Offer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.offers[offer.PreAuthorizedCode]; exists {
		return fmt.Errorf("offer with code %q already exists", offer.PreAuthorizedCode)
	}
	s.offers[offer.PreAuthorizedCode] = &offerEntry{offer: offer}
	return nil
}

// Consume implements [OfferStore].
func (s *MemoryOfferStore) Consume(_ context.Context, preAuthCode string) (*Offer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.offers[preAuthCode]
	if !ok {
		return nil, oid4vci.ErrOfferNotFound
	}
	if entry.used {
		return nil, oid4vci.ErrOfferAlreadyUsed
	}
	if time.Now().After(entry.offer.ExpiresAt) {
		return nil, oid4vci.ErrOfferExpired
	}
	entry.used = true
	return entry.offer, nil
}

// MemoryTokenStore is a thread-safe in-memory [TokenStore].
type MemoryTokenStore struct {
	mu      sync.Mutex
	records map[string]*AccessTokenRecord // keyed by token
}

// NewMemoryTokenStore creates a MemoryTokenStore.
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{records: make(map[string]*AccessTokenRecord)}
}

// Save implements [TokenStore].
func (s *MemoryTokenStore) Save(_ context.Context, record *AccessTokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.Token] = record
	return nil
}

// Get implements [TokenStore].
func (s *MemoryTokenStore) Get(_ context.Context, token string) (*AccessTokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[token]
	if !ok {
		return nil, oid4vci.ErrInvalidAccessToken
	}
	return r, nil
}

// RotateCNonce implements [TokenStore].
func (s *MemoryTokenStore) RotateCNonce(_ context.Context, token, newNonce string, expiresAt time.Time) (*AccessTokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[token]
	if !ok {
		return nil, oid4vci.ErrInvalidAccessToken
	}
	r.CNonce = newNonce
	r.CNonceExpiresAt = expiresAt
	return r, nil
}
