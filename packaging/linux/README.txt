GHOST PROXY - LINUX QUICK START
===============================

1. Extract this archive.
2. Run ./start-ghost-proxy.sh
   If your file manager does not offer "Run", open a terminal in this folder:
      chmod +x ghost-proxy start-ghost-proxy.sh ghost-proxy-settings.sh
      ./start-ghost-proxy.sh
3. The first time, Ghost Proxy asks for:
   - Server address: the host:port given by your provider
     (for example proxy.example.com:443)
   - TLS server name: press Enter to use the same host
   - CA certificate: leave blank if your provider uses a normal trusted
     certificate. If they gave you a server.crt file, enter its full path.
   - PSK: the hexadecimal key given by your provider
4. Leave the Ghost Proxy window open while you browse.

Connect your browser or app:
   Proxy type: SOCKS5
   Host:       127.0.0.1
   Port:       1080

To change the server address, PSK, or certificate later:
   Close Ghost Proxy, then run ./ghost-proxy-settings.sh.

Security:
   - Never share your PSK or ghost.env file.
   - Your settings are stored only in this folder.
