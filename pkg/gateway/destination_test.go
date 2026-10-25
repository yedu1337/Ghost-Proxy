package gateway

import "testing"

func TestDestinationPolicyRejectsPrivateAddresses(t *testing.T) {
	for _, target := range []string{"127.0.0.1:80", "169.254.169.254:80", "10.0.0.1:443", "[::1]:80", "[fe80::1]:443"} {
		if _, err := dialPublicDestination(target, nil); err == nil {
			t.Errorf("private destination %q accepted", target)
		}
	}
}
