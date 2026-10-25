GHOST PROXY SERVER - QUICK START
================================

RECOMMENDED: LINUX VPS
A rented Linux server with a public IP address is the simplest way to run a
gateway. You do not need a domain: the installer gets a free trusted
certificate for the server's public IP address.

Before you start:
   - Allow inbound TCP 80 and 443 in your cloud firewall/security group
     (for example, the AWS EC2 security group).
   - Allow inbound SSH so you can log in.

1. Download GhostProxy-Server-Linux-x64.tar.gz and extract it into an empty
   folder on the server.
2. Open a terminal in that folder and run:
      sudo ./install.sh

   The archive extracts its files directly; there is no inner folder.

   The installer asks for the public IP or domain. Press Enter to accept the
   detected public IP. An email address is optional (Let's Encrypt expiry
   notices).

   It installs the gateway as a systemd service, obtains and renews the
   certificate, and prints the invite text for your users.

3. Copy the invite text and send it privately to each user. It is also saved at:
      /etc/ghost-proxy/invite.txt

Useful commands:
   sudo systemctl status ghost-proxy
   sudo systemctl restart ghost-proxy
   sudo cat /etc/ghost-proxy/invite.txt

From the extracted package folder:
   sudo ./install.sh --new-psk      # rotate the PSK after a leak
   sudo ./install.sh                # upgrade; keeps the PSK and settings

The gateway listens on TCP 443. Port 80 is used only for certificate issuance
and renewal, so keep both ports open.

USING A DOMAIN
If you have a domain, point its DNS A/AAAA record at the server and run:
   sudo ./install.sh --host proxy.example.com --email you@example.com

WINDOWS SERVER (MANUAL)
1. Unzip this folder.
2. Double-click start-ghost-proxy-server.bat.
3. The wizard asks for the public host/port, certificate, and PSK.
   - Let's Encrypt certificates are easiest on the Linux installer.
   - For a self-signed certificate, send configs/server.crt to each user and
     have them enter its path in the client wizard.
4. Forward TCP 443 on your router to this computer, and give users:
      Server address: your-public-ip-or-domain:443
      PSK:            the key printed by the wizard

Use "GhostProxy Server Settings.bat" to change settings later.

SECURITY
   - The PSK is shared by all users. Anyone with it can use the gateway.
   - Never post the PSK or the invite publicly.
   - Keep /etc/ghost-proxy/environment and ghost.env private.
   - On Linux, the installer creates an unprivileged service user and
     restricts file permissions.

Full documentation and troubleshooting:
https://github.com/yedukrishna012/Ghost-Proxy
