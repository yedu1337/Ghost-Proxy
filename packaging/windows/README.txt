GHOST PROXY - WINDOWS QUICK START
=================================

1. Unzip this folder somewhere you can write to, such as Desktop or Documents.
2. Double-click GhostProxy.exe.
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
   Close Ghost Proxy, then double-click "GhostProxy Settings.bat".

Security:
   - Never share your PSK or ghost.env file.
   - Your settings are stored only in this folder.

Windows may show a SmartScreen warning because this build is not code-signed.
Click "More info" and then "Run anyway".
