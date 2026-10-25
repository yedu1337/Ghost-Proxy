GHOST PROXY - WINDOWS QUICK START
=================================

1. Unzip this folder somewhere you can write to, such as Desktop or Documents.
2. Double-click GhostProxy.exe.
3. The first time, Ghost Proxy asks for:
   - Server address: the host:port given by your provider
     (for example 203.0.113.10:443 or proxy.example.com:443)
   - TLS server name: press Enter to use the same host
   - CA certificate: leave blank if your provider uses a normal trusted
     certificate. If they gave you a server.crt file, enter its full path.
   - PSK: the hexadecimal key given by your provider
4. Leave the Ghost Proxy window open while you browse.

TEST THE CONNECTION
   Double-click "Test Ghost Proxy.bat".
   It makes a real HTTP request through the tunnel and tells you whether the
   gateway, certificate, and PSK are working.

CONNECT YOUR BROWSER
   Proxy type: SOCKS5
   Host:       127.0.0.1
   Port:       1080

   Edge/Chrome use the Windows proxy settings. Firefox has its own:
   Settings -> Network Settings -> Manual proxy configuration.

CHANGE SETTINGS LATER
   Close Ghost Proxy, then double-click "GhostProxy Settings.bat".

SECURITY
   - Never share your PSK or ghost.env file.
   - Your settings are stored only in this folder.
   - Anyone with the PSK can use the gateway.

Windows may show a SmartScreen warning because this build is not code-signed.
Click "More info" and then "Run anyway".

More help: https://github.com/yedukrishna012/Ghost-Proxy
