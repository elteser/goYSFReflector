# YSF Protocols

This page documents the various protocols used in YSFReflector communication.

## YSFS (Status)

- **Length**: 42 bytes
- **Description**: The YSFS packet is sent to provide status information about the reflector. Gaps must be filled with `0x20`.

| Field             | Length | Description                              | Example        | Hex Code                                |
|-------------------|--------|------------------------------------------|----------------|-----------------------------------------|
| Signature         | 4 bytes| Indicates the packet type.               | `YSFS`         | `59 53 46 53`                           |
| Software ID       | 5 bytes| Unique identifier for the software.      | `26298`        | `32 36 32 39 38`                        |
| YSF Server Name   | 30 bytes| The name of the reflector.               | `DE DF8VX`     | `44 45 20 44 46 38 56 20 20 20...` (filled with `0x20`) |
| Connection Count   | 3 bytes| The number of active connections.        | `999`          | `39 39 39`                              |

## YSFP (Login and Polling)

The `YSFP` protocol is used not only for initial login but also to periodically ping the reflector, confirming the client's connection.

### Function Description

The `handleYSFP` function processes incoming `YSFP` packets, managing both new client connections and periodic pings. If a client is already connected, it confirms the status by sending a response.

### Function Breakdown

```go
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
```

1. Packet Length Validation:
The packet must be exactly 14 bytes. If the length does not match, the function logs an error message and exits without further processing.

2. Extracting the Callsign:
The client's callsign is located at bytes 4 to 14 in the packet. The function extracts and trims any extra spaces.

3. Logging the Poll:
Once the callsign is extracted, the function logs the received YSFP packet, displaying both the callsign and the client's IP address.

4. Client Connection Check:
If the client (identified by the callsign) is already connected, the function logs a message and sends a response back to the client. It does not add the client to the list again.

5. Adding New Client:
If the client is not yet connected, the function adds the client (by their callsign) to the list of active clients, logs the new connection, and sends a response to confirm successful login.

### Explanation of the Response

Once a valid packet is processed, the function calls sendResponse to notify the client that their login or ping was successful. The response consists of several components that collectively confirm the reception of the YSFP packet. The initial bytes contain protocol-specific information, while the last part of the response conveys the status and the reflector's name. Padding in the server name are filled with `0x20` (space characters) to ensure the overall length of the packet remains consistent at 42 bytes. This design helps maintain the expected format and allows the receiving client to parse the response correctly.

```go
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
```

The YSFP response from the reflector is structured as follows and has a total length of 42 bytes:

| Offset | Hex Code                                             | Description                                     |
|--------|-----------------------------------------------------|-------------------------------------------------|
| 0000   | `08 00 00 00 00 00 00 02 00 01 04 06 ea b7 2f 21` | Header information, including packet metadata.  |
| 0010   | `44 f3 00 00 45 00 00 2a 76 96 40 00 40 11 01 71` | IP header details and routing information.      |
| 0020   | `55 d1 31 06 b0 02 8b e2 a4 13 c5 bb 00 16 c2 e3` | Additional routing and control information.      |
| 0030   | `59 53 46 50 52 45 46 4c 45 43 54 4f 52 20`      | Confirmation message, including the server name (e.g., `YSFREFLECTOR`) filled with `0x20` as padding. |





<!-- ## YSFP Response

The YSFP response from the reflector is structured as follows:

- **Length**: 42 bytes
- **Description**: This response confirms that the reflector has received the YSFP packet correctly. The response contains various header information followed by a confirmation message, including the server name and status.

| Offset | Hex Code                                             | Description                                     |
|--------|-----------------------------------------------------|-------------------------------------------------|
| 0000   | `08 00 00 00 00 00 00 02 00 01 04 06 ea b7 2f 21` | Header information, including packet metadata.  |
| 0010   | `44 f3 00 00 45 00 00 2a 76 96 40 00 40 11 01 71` | IP header details and routing information.      |
| 0020   | `55 d1 31 06 b0 02 8b e2 a4 13 c5 bb 00 16 c2 e3` | Additional routing and control information.      |
| 0030   | `59 53 46 50 52 45 46 4c 45 43 54 4f 52 20`      | Confirmation message, including the server name (e.g., `YSFREFLECTOR`) filled with `0x20` as padding. |

### Explanation of the Response

The response consists of several components that collectively confirm the reception of the YSFP packet. The initial bytes contain protocol-specific information, while the last part of the response conveys the status and the reflector's name. Padding in the server name are filled with `0x20` (space characters) to ensure the overall length of the packet remains consistent at 42 bytes. This design helps maintain the expected format and allows the receiving client to parse the response correctly.

 -->


<!-- ## YSFS (Status)

- **Length**: 42 bytes
- **Description**: The YSFS packet is sent to provide status information about the reflector.
- **Structure**:
  - Signature: `YSFS` (4 bytes)
  - Software ID: e.g., `26298` (5 bytes)
  - YSF Server Name: Reflector name (e.g., `DE DF8VX`) (30 bytes)
  - Connection Count: `999` (3 bytes) -->

<!-- ## YSFU (Unlink)

- **Length**: 14 bytes
- **Description**: This packet is sent when a client wants to unlink or disconnect from the YSFReflector.
- **Structure**:
  - Signature: `YSFU` (4 bytes)
  - Callsign: Client's callsign (10 bytes)

## YSFI (Information)

- **Length**: Variable depending on the content
- **Description**: YSFI packets contain information requests or responses related to the status of the YSFReflector.
- **Structure**:
  - Signature: `YSFI` (4 bytes)
  - Additional payload depending on the request.

## YSFP (Poll)

- **Length**: 14 bytes
- **Description**: Sent during the login process to register a client with the YSFReflector.
- **Structure**:
  - Signature: `YSFP` (4 bytes)
  - Callsign: Client's callsign (10 bytes)


## YSFD (Data)

- **Description**: Used for sending data packets.
- **Structure**: Custom depending on the data payload.

## YSFV (Voice)

- **Description**: Manages voice-related packets within the YSF communication system. -->
