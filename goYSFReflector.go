package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	reflectorID          = "26298"    // ID used during registration of the reflector
	reflectorName        = "DE DF8VX" // Example reflector name
	reflectorPort        = ":42003"   // Port used during registration of the reflector
	reflectorDescription = "Testing"  // Port used during registration of the reflector
	reflectorVersion     = "0.1"
	bufferSize           = 4096
	responseLength       = 14 // Length of the response
	ysfsResponseLength   = 42
	packetYSFDLength     = 155 // Length of YSFD packet
)

// Client structure for handling client versionrmation with a last activity timestamp
type Client struct {
	Address      *net.UDPAddr
	LastActivity time.Time
}

// Update the clients map to use the new Client structure
var clients = make(map[string]Client)

var (
	tx      [7]interface{}            // Tracking ongoing stream state
	lockTx  sync.Mutex                // Mutex for concurrent access to `tx`
	idStr   = 1                       // Unique stream ID
	rxLock  = make(map[int]bool)      // Lock for streams
	rxLockT = make(map[int]time.Time) // Timeout map for locked streams
)

// Function to start the UDP server and listen for packets
func main() {
	// Resolve UDP address
	addr, err := net.ResolveUDPAddr("udp", reflectorPort)
	if err != nil {
		log.Fatalf("Error resolving address: %v", err)
	}

	// Listen on the UDP port
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Error listening on UDP: %v", err)
	}
	defer conn.Close()

	log.Printf("Listening for UDP packets on %s\n", reflectorPort)

	buffer := make([]byte, bufferSize)

	// Start the goroutine to check for inactive clients
	go checkInactiveClients(60 * time.Second)

	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error receiving UDP packet: %v", err)
			continue
		}

		// Handle incoming packet in a separate goroutine to avoid blocking
		go handlePacket(buffer[:n], addr, conn)
	}
}

// Function to handle and parse received UDP packets
func handlePacket(packet []byte, addr *net.UDPAddr, conn *net.UDPConn) {
	if len(packet) < 4 {
		log.Printf("Packet too short from %s", addr.String())
		return
	}

	// Extract command from the packet
	cmd := string(packet[0:4])

	switch cmd {
	case "YSFP":
		handleYSFP(packet, addr, conn)
	case "YSFU":
		handleYSFU(packet, addr)
	case "YSFD":
		log.Printf("Handling YSFD command")
		handleYSFD(packet, addr, conn)
	case "YSFS":
		log.Printf("Handling YSFS command")
		handleYSFS(addr, conn)
	case "YSFV":
		log.Printf("Handling YSFV command")
		handleYSFV(addr, conn)
	case "YSFI":
		log.Printf("Handling YSFI command")
		// handleYSFI(packet, addr)
	default:
		log.Printf("Unknown command from %s: %s", addr.String(), cmd)
	}
}

// Function to handle YSFP (Login) packets
func handleYSFP(packet []byte, addr *net.UDPAddr, conn *net.UDPConn) {
	const packetLength = 14

	// Validate packet length
	if len(packet) != packetLength {
		log.Println("Invalid YSFP packet size")
		return
	}

	// Extract callsign (bytes 4-14)
	callsign := strings.TrimSpace(string(packet[4:14]))

	// Log the received packet
	log.Printf("Received YSFP poll from callsign: %s, IP: %s", callsign, addr.String())

	// Check if the client is already connected
	if client, exists := clients[callsign]; exists {
		// Update the last activity timestamp
		client.LastActivity = time.Now()
		clients[callsign] = client
		log.Printf("Client already connected: %s", callsign)
		sendResponse(addr, conn)
		return
	}

	// Add the client if not already connected
	clients[callsign] = Client{
		Address:      addr,
		LastActivity: time.Now(),
	}
	log.Printf("Client added: %s", callsign)

	// Send a response to confirm successful login
	sendResponse(addr, conn)
}

// Function to handle YSFU (Logout) packets
func handleYSFU(packet []byte, addr *net.UDPAddr) {
	const packetLength = 14

	// Validate packet length
	if len(packet) != packetLength {
		log.Println("Invalid YSFU packet size")
		return
	}

	// Extract callsign (bytes 4-14)
	callsign := strings.TrimSpace(string(packet[4:14]))

	// Log the logout attempt
	log.Printf("Received YSFU unlink request from callsign: %s, IP: %s", callsign, addr.String())

	// Check if the client exists and remove them
	if _, exists := clients[callsign]; exists {
		delete(clients, callsign)
		log.Printf("Client removed: %s", callsign)
	} else {
		log.Printf("Client not found for removal: %s", callsign)
	}
}

// Function to send a response indicating the status (login)
func sendResponse(addr *net.UDPAddr, conn *net.UDPConn) {
	response := make([]byte, responseLength)
	copy(response, reflectorName)
	_, err := conn.WriteToUDP(response, addr)
	if err != nil {
		log.Printf("Failed to send response: %v", err)
	} else {
		log.Printf("Sent response to %s", addr.String())
	}
}

// Function to handle YSFS packets and send the custom response
func handleYSFS(addr *net.UDPAddr, conn *net.UDPConn) {
	log.Printf("YSF server status enquiry from %s:%d", addr.IP.String(), addr.Port)

	// Limit the number of clients to 999
	clientCount := len(clients)
	if clientCount > 999 {
		clientCount = 999
	}

	// Prepare the response string according to the protocol
	// YSFS + Reflector ID (5 bytes) + Reflector Name (16 bytes) + Reflector Description (14 bytes) + Client Count (3 bytes)
	info := fmt.Sprintf("YSFS%-5s%-16s%-14s%03d", reflectorID, reflectorName, reflectorDescription, clientCount)

	// Send the response back to the client
	_, err := conn.WriteToUDP([]byte(info), addr)
	if err != nil {
		log.Printf("Failed to send YSFS response to %s:%d: %v", addr.IP.String(), addr.Port, err)
	} else {
		log.Printf("Sent YSFS response to %s:%d", addr.IP.String(), addr.Port)
	}
}

// Function to handle YSFD (Data) packets
func handleYSFD(packet []byte, addr *net.UDPAddr, conn *net.UDPConn) {
	if len(packet) != packetYSFDLength {
		log.Println("Invalid YSFD packet size")
		return
	}

	// Extract gateway callsign (bytes 4-14)
	gateway := strings.TrimSpace(string(packet[4:14]))

	// Extract source callsign (bytes 14-24)
	src := strings.TrimSpace(string(packet[14:24]))

	// Extract destination callsign (bytes 24-34)
	dest := strings.TrimSpace(string(packet[24:34]))

	// If no ongoing stream, create a new one
	if tx[0] == nil {
		lockTx.Lock()
		defer lockTx.Unlock()

		// Start a new stream
		tx[0] = 1 // New stream
		tx[2] = gateway
		tx[3] = src
		tx[4] = dest
		tx[5] = idStr
		tx[6] = time.Now()

		log.Printf("New stream started from %s to %s via %s\n", src, dest, gateway)
		idStr++
	} else {
		log.Printf("Ongoing stream already in progress from %s to %s via %s\n", tx[3], tx[4], tx[2])
	}

	// Route the packet to other clients except the origin
	routePacket(packet, addr, conn)
}

// Function to route packet to all clients except the origin
func routePacket(packet []byte, originAddr *net.UDPAddr, conn *net.UDPConn) {
	for callsign, client := range clients {
		// Skip the origin client
		if client.Address.IP.Equal(originAddr.IP) && client.Address.Port == originAddr.Port {
			log.Printf("Skipping origin client: %s", callsign)
			continue
		}

		// Send packet to other clients
		_, err := conn.WriteToUDP(packet, client.Address)
		if err != nil {
			log.Printf("Failed to send packet to %s (%s): %v", callsign, client.Address.String(), err)
		} else {
			log.Printf("Routed packet to %s (%s)", callsign, client.Address.String())
		}
	}
}

// Function to check for inactive clients and remove them
func checkInactiveClients(timeout time.Duration) {
	for {
		time.Sleep(10 * time.Second) // Check every 10 seconds

		// Get the current time
		now := time.Now()

		for callsign, client := range clients {
			// If the client has been inactive for longer than the timeout, remove them
			if now.Sub(client.LastActivity) > timeout {
				log.Printf("Client %s has been inactive for more than %s. Removing...", callsign, timeout)
				delete(clients, callsign)
			}
		}
	}
}

// Function to handle YSFV packets
func handleYSFV(addr *net.UDPAddr, conn *net.UDPConn) {
	// Decode the command and log it
	log.Printf("Received command YSFV from: %s:%d", addr.IP.String(), addr.Port)

	// Prepare the response: "YSFV" + "pYSFReflector" + " <version>"
	info := "YSFV" + "goYSFReflector" + " " + reflectorVersion

	// Send the response back to the client
	_, err := conn.WriteToUDP([]byte(info), addr)
	if err != nil {
		log.Printf("Failed to send YSFV response to %s:%d: %v", addr.IP.String(), addr.Port, err)
	} else {
		log.Printf("Sent YSFV response to %s:%d", addr.IP.String(), addr.Port)
	}
}
