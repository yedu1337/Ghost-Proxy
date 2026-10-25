GHOST PROXY - LINUX QUICK START
===============================

1. Extract this archive.
2. Run ./start-ghost-proxy.sh
   If your file manager does not offer "Run", open a terminal in this folder:
      chmod +x ghost-proxy start-ghost-proxy.sh ghost-proxy-settings.sh test-ghost-proxy.sh
      ./start-ghost-proxy.sh
3. The first time, Ghost Proxy asks for:
   - Server address: the host:port given by your provider
     (for example 203.0.113.10:443 or proxy.example.com:443)
   - TLS server name: press Enter to use the same host
   - CA certificate: leave blank if your provider uses a normal trusted
     certificate. If they gave you a server.crt file, enter its full path.
   - PSK: the hexadecimal key given by your provider
4. Leave the Ghost Proxy window open while you browse.

TEST THE CONNECTION
   Run ./test-ghost-proxy.sh
   It makes a real HTTP request through the tunnel and tells you whether the
   gateway, certificate, and PSK are working.

CONNECT YOUR BROWSER
   Proxy type: SOCKS5
   Host:       127.0.0.1
   Port:       1080

   Firefox: Settings -> Network Settings -> Manual proxy configuration.
   Chrome/Edge: use the system proxy settings, or launch the browser with
   --proxy-server="socks5://127.0.0.1:1080".

CHANGE SETTINGS LATER
   Close Ghost Proxy, then run ./ghost-proxy-settings.sh.

SECURITY
   - Never share your PSK or ghost.env file.
   - Your settings are stored only in this folder.
   - Anyone with the PSK can use the gateway.

More help: https://github.com/yedukrishna012/Ghost-Proxy
