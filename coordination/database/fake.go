package database

import (
	"context"
	"errors"
	"sync"
)

// FakeStore uses a map to store devices temporarily in memory.
type FakeStore struct {
	mu      sync.RWMutex
	devices map[string]Device
}

// NewFakeStore initializes the map.
func NewFakeStore() *FakeStore {
	return &FakeStore{
		devices: make(map[string]Device),
	}
}

func (s *FakeStore) RegisterDevice(ctx context.Context, dev Device) error {
	s.mu.Lock() // Lock for writing
	defer s.mu.Unlock()

	s.devices[dev.DeviceID] = dev
	return nil
}

func (s *FakeStore) GetDevice(ctx context.Context, deviceID string) (*Device, error) {
	s.mu.RLock() // Lock for reading
	defer s.mu.RUnlock()

	dev, exists := s.devices[deviceID]
	if !exists {
		return nil, errors.New("device not found")
	}
	return &dev, nil
}

func (s *FakeStore) GetAllDevices(ctx context.Context) ([]Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var all []Device
	for _, dev := range s.devices {
		all = append(all, dev)
	}
	return all, nil
}
