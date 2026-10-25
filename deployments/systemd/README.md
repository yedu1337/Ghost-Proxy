# systemd and Let's Encrypt

The easiest path is the Linux server package installer:

```bash
tar -xzf GhostProxy-Server-Linux-x64.tar.gz
cd GhostProxy-Server-Linux-x64
sudo ./install.sh
```

It creates the `ghost-proxy` user, installs the binary at
`/opt/ghost-proxy/ghost-proxy-server`, writes `/etc/ghost-proxy/server.yaml`
and `/etc/ghost-proxy/environment`, obtains a Let's Encrypt certificate,
installs `ghost-proxy.service`, and enables a daily renewal timer. It can use a
public IP address, so no domain is required. See the main
[README](../../README.md) for the full operator guide.

## Manual installation

1. Create the service account and directories:

   ```bash
   sudo groupadd --system ghost-proxy
   sudo useradd --system --gid ghost-proxy \
     --home-dir /var/lib/ghost-proxy --create-home \
     --shell /usr/sbin/nologin ghost-proxy
   sudo install -d -m 0755 /opt/ghost-proxy
   sudo install -d -m 0750 -o root -g ghost-proxy /etc/ghost-proxy
   sudo install -m 0755 ghost-proxy-server /opt/ghost-proxy/
   ```

2. Create `/etc/ghost-proxy/environment`:

   ```text
   GHOST_PSK=<64 hex characters>
   ```

   ```bash
   sudo chown root:ghost-proxy /etc/ghost-proxy/environment
   sudo chmod 0640 /etc/ghost-proxy/environment
   ```

3. Install Certbot 5.4 or newer in a private virtual environment. Certbot 5.4
   requires Python 3.10 or newer. This example is for Debian/Ubuntu; adapt the
   package names for your distribution.

   ```bash
   sudo apt-get update
   sudo apt-get install -y python3 python3-venv
   sudo python3 -m venv /opt/certbot
   sudo /opt/certbot/bin/python -m pip install --upgrade pip
   sudo /opt/certbot/bin/pip install 'certbot>=5.4'
   ```

4. Obtain a certificate with Certbot's standalone HTTP-01 flow. Port 80 must
   be free and reachable from the internet.

   For a public IP (short-lived profile):

   ```bash
   sudo /opt/certbot/bin/certbot certonly --standalone \
     --preferred-profile shortlived --ip-address 203.0.113.10
   ```

   For a domain:

   ```bash
   sudo /opt/certbot/bin/certbot certonly --standalone -d proxy.example.com
   ```

5. Run the setup wizard to copy the certificate and write the final config.
   Replace `203.0.113.10` with your IP address or domain name; the Certbot
   lineage is normally named after it.

   ```bash
   sudo /opt/ghost-proxy/ghost-proxy-server --setup-only \
     --config /etc/ghost-proxy/server.yaml \
     --env-file /etc/ghost-proxy/environment \
     --public-host 203.0.113.10 \
     --cert-file /etc/letsencrypt/live/203.0.113.10/fullchain.pem \
     --key-file /etc/letsencrypt/live/203.0.113.10/privkey.pem \
     --non-interactive --force
   ```

   The service user needs group read access to the key, config, and
   environment file:

   ```bash
   sudo chown root:ghost-proxy /etc/ghost-proxy/server.key \
     /etc/ghost-proxy/server.crt /etc/ghost-proxy/server.yaml \
     /etc/ghost-proxy/environment
   sudo chmod 0640 /etc/ghost-proxy/server.key \
     /etc/ghost-proxy/server.yaml /etc/ghost-proxy/environment
   sudo chmod 0644 /etc/ghost-proxy/server.crt
   ```

6. Install the service:

   ```bash
   sudo install -m 0644 ghost-proxy.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now ghost-proxy
   ```

7. Install the renewal hook and timer. The hook only copies the certificate
   whose lineage matches `/etc/ghost-proxy/renewal-cert-name`, so renewing an
   unrelated certificate cannot replace the gateway certificate.

   ```bash
   # Replace the IP with your domain name if you requested a domain certificate.
   echo "203.0.113.10" | sudo tee /etc/ghost-proxy/renewal-cert-name
   sudo install -d /etc/letsencrypt/renewal-hooks/deploy
   sudo install -m 0755 certbot-deploy-hook.sh \
     /etc/letsencrypt/renewal-hooks/deploy/ghost-proxy.sh
   sudo install -m 0644 ghost-proxy-certbot-renew.service \
     ghost-proxy-certbot-renew.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now ghost-proxy-certbot-renew.timer
   ```

   The timer runs `/opt/certbot/bin/certbot renew --quiet`. If Certbot is
   installed elsewhere, edit `ExecStart` in
   `ghost-proxy-certbot-renew.service` before enabling the timer.

## Notes

- Certbot 5.4 requires Python 3.10 or newer. The installer picks the newest
  compatible Python and adds Python 3.11 on Amazon Linux when needed.
- Certificates are loaded at startup. The deploy hook restarts the gateway
  after a successful renewal so it picks up the new certificate.
- Let's Encrypt IP certificates are valid for about six days, so keep port 80
  reachable and the renewal timer enabled.
- Check the configuration at any time:

  ```bash
  sudo /opt/ghost-proxy/ghost-proxy-server --check \
    --config /etc/ghost-proxy/server.yaml \
    --env-file /etc/ghost-proxy/environment
  ```
