GHOST PROXY SERVER - QUICK START
================================

This package is for the machine that runs the gateway.

1. Put your TLS certificate and private key in:
      configs/server.crt
      configs/server.key
2. Create ghost.env in this folder containing one line:
      GHOST_PSK=<64 hexadecimal characters>
   You can generate a key with:
      openssl rand -hex 32
3. Start the gateway with the provided launcher:
      Windows: double-click start-ghost-proxy-server.bat
      Linux:   ./start-ghost-proxy-server.sh
   The launcher reads ghost.env and runs the gateway on 0.0.0.0:443
   (see configs/server.yaml).
4. Allow TCP port 443 through your firewall and point your domain at this
   machine.
5. Give each user:
      Server address: your-domain:443
      PSK:            the key from ghost.env
      server.crt:     only if you use a self-signed certificate

For certificate generation, systemd, Docker, Nginx decoy, and full server
documentation, see the repository README.
