package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/devlup-labs/Ghostwire/client-backend/wireguard"
)

func main() {
	fmt.Println("[GhostWire Client] Initializing node...")

	// 1. Generate local keys and device instance
	node, err := wireguard.NewNode()
	if err != nil {
		panic(err)
	}

	// 2. Start the TUN interface on port 51820.
	// Passing "utun" lets macOS auto-assign a number (e.g., utun3)
	realIface, err := node.Start("utun", 51820)
	if err != nil {
		panic(fmt.Sprintf("Failed to start WireGuard interface: %v", err))
	}
	fmt.Printf("[GhostWire Client] Virtual interface '%s' is up!\n", realIface)

	// 3. Register with your coordination server API
	registerPayload, _ := json.Marshal(map[string]any{
		"deviceId":   "device-001",
		"oAuthToken": "dummy-token",
		"isHealthy":  true,
		"publicKey":  node.PublicKey.String(), // Safe to send standard Base64 to server
		"endpoint":   "127.0.0.1:51820",
	})

	resp, err := http.Post("http://127.0.0.1:8000/api/v1/register", "application/json", bytes.NewBuffer(registerPayload))
	if err != nil {
		fmt.Printf("[Error] Failed to reach coordination server: %v\n", err)
	} else {
		fmt.Printf("[GhostWire Client] Registered with server. Status: %d\n", resp.StatusCode)
		resp.Body.Close()
	}

	// Keep client running
	select {}
}
