package main

import (
	"fmt"
	"log"
	"net"
	"strings"
)

const (
	bufferSize         = 4096
	udpPort            = ":42003"        // Port used during registration of the reflector
	reflectorName      = "YSFPREFLECTOR" // Example reflector name
	responseLength     = 14              // Length of the response
	reflectorID        = "26298"         // ID used during registration of the reflector
	ysfsResponseLength = 42
)

// Client structure for handling client information
var clients = make(map[string]*net.UDPAddr)

// Function to start the UDP server and listen for packets
func main() {
	// Resolve UDP address
	addr, err := net.ResolveUDPAddr("udp", udpPort)
	if err != nil {
		log.Fatalf("Error resolving address: %v", err)
	}

	// Listen on the UDP port
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Error listening on UDP: %v", err)
	}
	defer conn.Close()

	log.Printf("Listening for UDP packets on %s\n", udpPort)

	buffer := make([]byte, bufferSize)

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
		// handleYSFD(packet, addr, conn)
	case "YSFS":
		handleYSFS(addr, conn)
	case "YSFV":
		log.Printf("Handling YSFV command")
		// handleYSFV(addr)
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
	if _, exists := clients[callsign]; exists {
		log.Printf("Client already connected: %s", callsign)
		sendResponse(addr, conn)
		return
	}

	// Add the client if not already connected
	clients[callsign] = addr
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

// Function to handle YSFS packets and send the custom 42-byte response
func handleYSFS(addr *net.UDPAddr, conn *net.UDPConn) {
	log.Printf("Received YSFS packet from %s", addr.String())

	// Prepare the 42-byte response
	response := make([]byte, ysfsResponseLength)

	// First 4 bytes: Signature "YSFS"
	copy(response[0:], "YSFS")

	// Next 5 bytes: Software ID
	copy(response[4:], reflectorID)

	// Next 30 bytes: YSF Server Name, padded with spaces
	serverName := fmt.Sprintf("%-30s", reflectorName)
	copy(response[9:], serverName)

	// Last 3 bytes: Connection count (000-999)
	connectionCount := fmt.Sprintf("%03d", len(clients))
	copy(response[39:], connectionCount)

	// Send the 42-byte response
	_, err := conn.WriteToUDP(response, addr)
	if err != nil {
		log.Printf("Failed to send YSFS response: %v", err)
	} else {
		log.Printf("Sent YSFS response to %s", addr.String())
	}
}
