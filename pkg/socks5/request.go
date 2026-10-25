package socks5

import (
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

type Request struct {
	Command byte
	Address string
}

func readRequest(conn net.Conn) (*Request, error) {
	header := make([]byte, 4)

	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read request header: %w", err)
	}

	if header[0] != socks5Version {
		return nil, fmt.Errorf("unsupported SOCKS version: 0x%02x", header[0])
	}

	if header[1] != cmdConnect {
		return nil, fmt.Errorf("unsupported SOCKS command: 0x%02x", header[1])
	}

	if header[2] != 0x00 {
		return nil, fmt.Errorf("invalid reserved byte: 0x%02x", header[2])
	}

	var host string

	switch header[3] {
	case atypIPv4:
		addr := make([]byte, net.IPv4len)

		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, fmt.Errorf("read IPv4 address: %w", err)
		}

		host = net.IP(addr).String()

	case atypDomain:
		length := make([]byte, 1)

		if _, err := io.ReadFull(conn, length); err != nil {
			return nil, fmt.Errorf("read domain length: %w", err)
		}

		if length[0] == 0 {
			return nil, fmt.Errorf("domain length cannot be zero")
		}

		domain := make([]byte, int(length[0]))

		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, fmt.Errorf("read domain: %w", err)
		}

		host = string(domain)

	case atypIPv6:
		addr := make([]byte, net.IPv6len)

		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, fmt.Errorf("read IPv6 address: %w", err)
		}

		host = net.IP(addr).String()

	default:
		return nil, fmt.Errorf("unsupported address type: 0x%02x", header[3])
	}

	portBytes := make([]byte, 2)

	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return nil, fmt.Errorf("read destination port: %w", err)
	}

	port := int(portBytes[0])<<8 | int(portBytes[1])

	return &Request{
		Command: header[1],
		Address: net.JoinHostPort(host, strconv.Itoa(port)),
	}, nil
}
