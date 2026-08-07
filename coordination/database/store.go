package database

import "context"

// Device represents a WireGuard node in the mesh
type Device struct {
	DeviceID  string
	PublicKey string // Base64 WG Key
	Endpoint  string // Public IP:Port
	VirtualIP string // e.g., "10.0.0.5/32"
}

// Store defines the exact methods your APIs need to function.
type Store interface {
	RegisterDevice(ctx context.Context, dev Device) error
	GetDevice(ctx context.Context, deviceID string) (*Device, error)
	GetAllDevices(ctx context.Context) ([]Device, error)
}
