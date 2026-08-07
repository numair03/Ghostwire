package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/devlup-labs/Ghostwire/client-backend/wireguard"
)

type RegisterResponse struct {
	VirtualIP string `json:"virtualIp"`
}

type CheckinResponse struct {
	Allowlist map[string]struct {
		PublicKey     []byte `json:"PublicKey"`
		PublicAddress string `json:"PublicAddress"`
		GwIp          string `json:"GwIp"`
	} `json:"allowlist"`
}

func main() {
	deviceID := flag.String("id", "device-001", "Unique device ID")
	port := flag.Int("port", 51820, "WireGuard listen port")
	fallbackIP := flag.String("ip", "10.0.0.2", "Virtual IP")
	serverURL := flag.String("server", "http://127.0.0.1:8000", "Coordination server URL")
	physicalIP := flag.String("endpoint-ip", "127.0.0.1", "Physical LAN IP of this machine")
	flag.Parse()

	fmt.Printf("[GhostWire Client] Initializing %s...\n", *deviceID)

	node, err := wireguard.NewNode()
	if err != nil {
		panic(err)
	}

	realIface, err := node.Start("utun", *port)
	if err != nil {
		panic(err)
	}
	fmt.Printf("[GhostWire Client] Interface '%s' up!\n", realIface)

	// 1. REGISTRATION
	registerPayload, _ := json.Marshal(map[string]any{
		"deviceId":   *deviceID,
		"oAuthToken": "dummy",
		"isHealthy":  true,
		"publicKey":  node.PublicKey.String(),
		"endpoint":   fmt.Sprintf("%s:%d", *physicalIP, *port),
	})

	resp, err := http.Post(*serverURL+"/api/v1/register", "application/json", bytes.NewBuffer(registerPayload))
	if err != nil {
		panic(fmt.Sprintf("Server unreachable at %s: %v", *serverURL, err))
	}
	defer resp.Body.Close()

	// FIX: Renamed from regResp to registration to avoid the &reg HTML entity bug
	var registration RegisterResponse
	json.NewDecoder(resp.Body).Decode(&registration)

	if registration.VirtualIP == "" {
		registration.VirtualIP = *fallbackIP
	}
	fmt.Printf("[GhostWire] Assigned Virtual IP: %s\n", registration.VirtualIP)

	// 2. OS INTERFACE CONFIGURATION
	setInterfaceIP(realIface, registration.VirtualIP)

	// 3. HEARTBEAT
	ticker := time.NewTicker(10 * time.Second)
	runCheckin(node, *deviceID, registration.VirtualIP, *port, *serverURL)
	for range ticker.C {
		runCheckin(node, *deviceID, registration.VirtualIP, *port, *serverURL)
	}
}

func runCheckin(node *wireguard.Node, id, ip string, port int, server string) {
	checkinPayload, _ := json.Marshal(map[string]any{
		"deviceId": id,
		"gwIp":     ip,
		"gwPort":   port,
	})

	req, _ := http.NewRequest("POST", server+"/api/v1/checkin", bytes.NewBuffer(checkinPayload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var checkinResp CheckinResponse
	json.NewDecoder(resp.Body).Decode(&checkinResp)

	var peers []wireguard.PeerConfig
	for _, entry := range checkinResp.Allowlist {
		peers = append(peers, wireguard.PeerConfig{
			PublicKey: string(entry.PublicKey),
			Endpoint:  entry.PublicAddress,
			AllowedIP: entry.GwIp + "/32",
		})
	}
	node.SyncPeers(peers)
}

func setInterfaceIP(iface, ip string) error {
	if runtime.GOOS == "darwin" {
		return exec.Command("ifconfig", iface, ip, ip, "up").Run()
	}
	exec.Command("ip", "addr", "add", ip+"/32", "dev", iface).Run()
	return exec.Command("ip", "link", "set", "dev", iface, "up").Run()
}
