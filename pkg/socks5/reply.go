package socks5

import (
	"fmt"
	"net"
)

const (
	replySucceeded         = 0x00
	replyGeneralFailure    = 0x01
	replyConnectionRefused = 0x05
)

func sendReply(conn net.Conn, reply byte, boundAddr net.Addr) error {
	ip, port := "0.0.0.0", 0

	if tcpAddr, ok := boundAddr.(*net.TCPAddr); ok {
		if tcpAddr.IP != nil {
			ip = tcpAddr.IP.String()
		}
		port = tcpAddr.Port
	}

	parsedIP := net.ParseIP(ip)

	if parsedIP == nil {
		return fmt.Errorf("invalid bound IP address: %q", ip)
	}

	var addressType byte
	var address []byte

	if ipv4 := parsedIP.To4(); ipv4 != nil {
		addressType = atypIPv4
		address = ipv4
	} else {
		addressType = atypIPv6
		address = parsedIP.To16()
	}

	if address == nil {
		return fmt.Errorf("unable to encode bound IP address")
	}

	response := make([]byte, 0, 4+len(address)+2)

	response = append(response,
		socks5Version,
		reply,
		0x00,
		addressType,
	)

	response = append(response, address...)
	response = append(response, byte(port>>8), byte(port))

	_, err := conn.Write(response)
	if err != nil {
		return fmt.Errorf("send SOCKS5 reply: %w", err)
	}

	return nil
}
