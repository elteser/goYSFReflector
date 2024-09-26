package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// reflectorID          = "26298"    // Reflector ID used for registration
	// reflectorName        = "DE DF8VX" // Reflector name
	// reflectorPort        = ":42003"   // UDP port for the reflector
	// reflectorDescription = "Testing"  // Reflector description
	// reflectorVersion     = "0.1"
	bufferSize    = 4096
	clientTimeout = 60 * time.Second
)

type Config struct {
	ReflectorID          string `json:"reflectorID"`
	ReflectorName        string `json:"reflectorName"`
	ReflectorPort        string `json:"reflectorPort"`
	ReflectorDescription string `json:"reflectorDescription"`
	ReflectorVersion     string `json:"reflectorVersion"`
}

// Client represents the connected client with its last activity timestamp
type Client struct {
	Address      *net.UDPAddr
	LastActivity time.Time
}

var (
	clients = make(map[string]Client) // Map of connected clients
	tx      [7]interface{}            // Tracking ongoing stream state
	lockTx  sync.Mutex                // Mutex for concurrent access to `tx`
	idStr   = 1                       // Unique stream ID
)

func loadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to open config file: %v", err)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read config file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(bytes, &config); err != nil {
		return nil, fmt.Errorf("unable to parse config file: %v", err)
	}

	return &config, nil
}

func main() {
	// Load the configuration
	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Now use the config to set up the UDP server
	addr, err := net.ResolveUDPAddr("udp", config.ReflectorPort)
	checkError(err, "Error resolving UDP address")

	conn, err := net.ListenUDP("udp", addr)
	checkError(err, "Error listening on UDP")
	defer conn.Close()

	log.Printf("Listening for UDP packets on %s\n", config.ReflectorPort)
	go checkInactiveClients()

	buffer := make([]byte, bufferSize)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error receiving UDP packet: %v", err)
			continue
		}
		go handlePacket(buffer[:n], addr, conn, config) // Pass config here
	}
}

func handlePacket(packet []byte, addr *net.UDPAddr, conn *net.UDPConn, config *Config) {
	if len(packet) < 4 {
		log.Printf("Packet too short from %s", addr.String())
		return
	}

	cmd := string(packet[:4])
	switch cmd {
	case "YSFP":
		handleYSFP(packet, addr, conn, config)
	case "YSFU":
		handleYSFU(packet, addr)
	case "YSFD":
		handleYSFD(packet, addr, conn)
	case "YSFS":
		handleYSFS(addr, conn, config)
	case "YSFV":
		handleYSFV(addr, conn, config)
	default:
		log.Printf("Unknown command from %s: %s", addr.String(), cmd)
	}
}

func handleYSFP(packet []byte, addr *net.UDPAddr, conn *net.UDPConn, config *Config) {
	const packetLength = 14
	if len(packet) != packetLength {
		log.Println("Invalid YSFP packet size")
		return
	}

	callsign := strings.TrimSpace(string(packet[4:14]))
	log.Printf("Received YSFP poll from callsign: %s, IP: %s", callsign, addr.String())

	if client, exists := clients[callsign]; exists {
		client.LastActivity = time.Now()
		clients[callsign] = client
		log.Printf("Client already connected: %s", callsign)
	} else {
		clients[callsign] = Client{Address: addr, LastActivity: time.Now()}
		log.Printf("Client added: %s", callsign)
	}

	// Pass the config to the sendResponse function
	sendResponse(addr, conn, config)
}

// Handles YSFU (Logout) packets
func handleYSFU(packet []byte, addr *net.UDPAddr) {
	const packetLength = 14
	if len(packet) != packetLength {
		log.Println("Invalid YSFU packet size")
		return
	}

	callsign := strings.TrimSpace(string(packet[4:14]))
	log.Printf("Received YSFU unlink request from callsign: %s, IP: %s", callsign, addr.String())

	if _, exists := clients[callsign]; exists {
		delete(clients, callsign)
		log.Printf("Client removed: %s", callsign)
	} else {
		log.Printf("Client not found: %s", callsign)
	}
}

// Sends a generic response
func sendResponse(addr *net.UDPAddr, conn *net.UDPConn, config *Config) {
	response := make([]byte, len(config.ReflectorName))
	copy(response, config.ReflectorName)
	_, err := conn.WriteToUDP(response, addr)
	checkError(err, "Failed to send response")
}

// Handles YSFS packets (Server Status Inquiry)
func handleYSFS(addr *net.UDPAddr, conn *net.UDPConn, config *Config) {
	log.Printf("YSF server status enquiry from %s:%d", addr.IP.String(), addr.Port)

	clientCount := min(len(clients), 999)
	info := fmt.Sprintf("YSFS%-5s%-16s%-14s%03d", config.ReflectorID, config.ReflectorName, config.ReflectorDescription, clientCount)

	_, err := conn.WriteToUDP([]byte(info), addr)
	checkError(err, fmt.Sprintf("Failed to send YSFS response to %s", addr.String()))
}

// Handles YSFD (Data) packets
func handleYSFD(packet []byte, addr *net.UDPAddr, conn *net.UDPConn) {
	const packetYSFDLength = 155

	if len(packet) != packetYSFDLength {
		log.Println("Invalid YSFD packet size")
		return
	}

	gateway := strings.TrimSpace(string(packet[4:14]))
	src := strings.TrimSpace(string(packet[14:24]))
	dest := strings.TrimSpace(string(packet[24:34]))

	lockTx.Lock()
	defer lockTx.Unlock()

	if tx[0] == nil {
		startNewStream(gateway, src, dest)
	} else {
		log.Printf("Ongoing stream from %s to %s via %s", tx[3], tx[4], tx[2])
	}

	routePacket(packet, addr, conn)
}

// Starts a new data stream
func startNewStream(gateway, src, dest string) {
	tx[0] = 1
	tx[2] = gateway
	tx[3] = src
	tx[4] = dest
	tx[5] = idStr
	tx[6] = time.Now()

	log.Printf("New stream started from %s to %s via %s", src, dest, gateway)
	idStr++
}

// Routes a packet to all clients except the origin
func routePacket(packet []byte, originAddr *net.UDPAddr, conn *net.UDPConn) {
	for callsign, client := range clients {
		if isOrigin(client.Address, originAddr) {
			continue
		}

		_, err := conn.WriteToUDP(packet, client.Address)
		if err != nil {
			log.Printf("Failed to send packet to %s (%s): %v", callsign, client.Address.String(), err)
		} else {
			log.Printf("Routed packet to %s (%s)", callsign, client.Address.String())
		}
	}
}

// Checks if the client is the origin of the packet
func isOrigin(clientAddr, originAddr *net.UDPAddr) bool {
	return clientAddr.IP.Equal(originAddr.IP) && clientAddr.Port == originAddr.Port
}

// Checks for inactive clients and removes them
func checkInactiveClients() {
	for {
		time.Sleep(10 * time.Second)
		now := time.Now()
		for callsign, client := range clients {
			if now.Sub(client.LastActivity) > clientTimeout {
				log.Printf("Client %s inactive for more than %v. Removing...", callsign, clientTimeout)
				delete(clients, callsign)
			}
		}
	}
}

// Handles YSFV packets (Version Inquiry)
func handleYSFV(addr *net.UDPAddr, conn *net.UDPConn, config *Config) {
	log.Printf("Received YSFV command from: %s:%d", addr.IP.String(), addr.Port)
	info := fmt.Sprintf("YSFVgoYSFReflector %s", config.ReflectorVersion)

	_, err := conn.WriteToUDP([]byte(info), addr)
	checkError(err, fmt.Sprintf("Failed to send YSFV response to %s", addr.String()))
}

// Utility function to log and exit on error
func checkError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}

// Utility function to return the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
