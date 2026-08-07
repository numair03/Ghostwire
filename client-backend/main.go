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

const defaultKeepaliveSeconds = 25

type RegisterResponse struct {
	VirtualIP string `json:"virtualIp"`
}

type CheckinResponse struct {
	Allowlist map[string]struct {
		PublicKey     string `json:"PublicKey"`
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

	var registration RegisterResponse
	json.NewDecoder(resp.Body).Decode(&registration)

	if registration.VirtualIP == "" {
		// FIX: Fail loudly instead of silently falling back. A silent fallback
		// to the same default IP on both peers causes an IP collision that is
		// nearly impossible to diagnose from a ping timeout alone.
		panic(fmt.Sprintf(
			"[GhostWire] server did not assign a virtual IP for device '%s' — refusing to use fallback '%s' silently",
			*deviceID, *fallbackIP,
		))
	}
	fmt.Printf("[GhostWire] Assigned Virtual IP: %s\n", registration.VirtualIP)

	// 2. OS INTERFACE CONFIGURATION
	if err := setInterfaceIP(realIface, registration.VirtualIP); err != nil {
		fmt.Printf("[GhostWire] WARNING: setInterfaceIP failed: %v\n", err)
	}

	// 3. HEARTBEAT
	ticker := time.NewTicker(10 * time.Second)
	runCheckin(node, realIface, *deviceID, registration.VirtualIP, *port, *serverURL)
	for range ticker.C {
		runCheckin(node, realIface, *deviceID, registration.VirtualIP, *port, *serverURL)
	}
}

func runCheckin(node *wireguard.Node, iface, id, ip string, port int, server string) {
	checkinPayload, _ := json.Marshal(map[string]any{
		"deviceId": id,
		"gwIp":     ip,
		"gwPort":   port,
	})

	req, _ := http.NewRequest("POST", server+"/api/v1/checkin", bytes.NewBuffer(checkinPayload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("[GhostWire] checkin request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var checkinResp CheckinResponse
	if err := json.NewDecoder(resp.Body).Decode(&checkinResp); err != nil {
		fmt.Printf("[GhostWire] checkin response decode failed: %v\n", err)
		return
	}

	var peers []wireguard.PeerConfig
	for peerID, entry := range checkinResp.Allowlist {
		if entry.PublicKey == "" || entry.GwIp == "" {
			fmt.Printf("[GhostWire] WARNING: skipping malformed allowlist entry for '%s'\n", peerID)
			continue
		}
		peers = append(peers, wireguard.PeerConfig{
			PublicKey:           entry.PublicKey,
			Endpoint:            entry.PublicAddress,
			AllowedIP:           entry.GwIp + "/32",
			PersistentKeepalive: defaultKeepaliveSeconds,
		})
	}

	if err := node.SyncPeers(peers); err != nil {
		fmt.Printf("[GhostWire] SyncPeers error: %v\n", err)
	}

	syncRoutes(iface, peers)
}

// syncRoutes ensures the OS routing table sends traffic for each peer's
// AllowedIP into the WireGuard interface. WireGuard itself only decides
// what to do with packets once they arrive on the tun device — it does not
// modify the OS routing table, so wg-quick's job has to be done manually here.
func syncRoutes(iface string, peers []wireguard.PeerConfig) {
	for _, p := range peers {
		addRoute(iface, p.AllowedIP)
	}
}

func addRoute(iface, cidr string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("route", "-q", "-n", "add", "-inet", cidr, "-interface", iface)
	} else {
		cmd = exec.Command("ip", "route", "add", cidr, "dev", iface)
	}

	out, err := cmd.CombinedOutput()
	if err != nil && !bytes.Contains(out, []byte("exists")) && !bytes.Contains(out, []byte("File exists")) {
		fmt.Printf("[GhostWire] route add %s via %s failed: %v (%s)\n", cidr, iface, err, out)
	}
}

func setInterfaceIP(iface, ip string) error {
	if runtime.GOOS == "darwin" {
		return exec.Command("ifconfig", iface, ip, ip, "up").Run()
	}
	if err := exec.Command("ip", "addr", "add", ip+"/32", "dev", iface).Run(); err != nil {
		return err
	}
	return exec.Command("ip", "link", "set", "dev", iface, "up").Run()
}
