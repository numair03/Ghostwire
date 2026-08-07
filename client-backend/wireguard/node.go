package wireguard

import (
	"encoding/hex"
	"fmt"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes" // <-- The corrected import path
)

// PeerConfig holds data received from the coordination server checkin
type PeerConfig struct {
	PublicKey string
	Endpoint  string
	AllowedIP string
}

type Node struct {
	PrivateKey wgtypes.Key
	PublicKey  wgtypes.Key
	Device     *device.Device
}

// NewNode generates local cryptographic keys
func NewNode() (*Node, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return &Node{
		PrivateKey: key,
		PublicKey:  key.PublicKey(),
	}, nil
}

// Start creates the virtual TUN interface in the OS
func (n *Node) Start(ifaceName string, listenPort int) (string, error) { // <-- changed return type
	tunDev, err := tun.CreateTUN(ifaceName, 1420)
	if err != nil {
		return "", err
	}

	// Ask the OS what it actually named the interface
	realName, _ := tunDev.Name()

	logger := device.NewLogger(device.LogLevelError, "[GhostWire] ")
	n.Device = device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	uapiConfig := fmt.Sprintf(
		"private_key=%s\nlisten_port=%d\n",
		hex.EncodeToString(n.PrivateKey[:]),
		listenPort,
	)

	if err := n.Device.IpcSet(uapiConfig); err != nil {
		return realName, err
	}

	return realName, n.Device.Up()
}

// SyncPeers registers remote peers into the engine
func (n *Node) SyncPeers(peers []PeerConfig) error {
	var ipcBuf string

	for _, p := range peers {
		key, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			continue
		}

		// FIX: Use hex.EncodeToString for the peer's public key
		ipcBuf += fmt.Sprintf(
			"public_key=%s\nendpoint=%s\nallowed_ip=%s\n",
			hex.EncodeToString(key[:]),
			p.Endpoint,
			p.AllowedIP,
		)
	}

	return n.Device.IpcSet(ipcBuf)
}
