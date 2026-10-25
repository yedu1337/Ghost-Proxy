package socks5

import (
	"fmt"
	"net"
)

func connectToTarget(request *Request, dial DialFunc) (net.Conn, error) {
	if request == nil {
		return nil, fmt.Errorf("request is nil")
	}

	if request.Command != cmdConnect {
		return nil, fmt.Errorf("unsupported command: 0x%02x", request.Command)
	}

	if dial == nil {
		dial = func(address string) (net.Conn, error) {
			return net.Dial("tcp", address)
		}
	}

	conn, err := dial(request.Address)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", request.Address, err)
	}

	return conn, nil
}
