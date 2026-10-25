WebTAK Server for Windows
=========================

Your own TAK server for ATAK, iTAK and WinTAK - no extra software needed.

TRY IT (portable)
  Double-click webtak-server.exe. A window opens with the server, and your browser
  shows the setup page (http://localhost:8080/). Set the admin password - done.
  If Windows asks whether to allow network access: click "Allow".
  The server runs as long as the window is open. Data is stored in the folder "takdata".

INSTALL (runs in the background and starts with Windows)
  Double-click Install.bat and confirm the administrator question.
  This copies the program to C:\Program Files\WebTAK Server, keeps your data in
  C:\ProgramData\WebTAK Server (data of the portable test is taken over), opens the
  Windows firewall and starts the server. Web interface: http://localhost:8080/

UPDATE
  Download the new version and run Install.bat again. Users, certificates and
  links stay.

REMOVE
  Uninstall.bat (your data stays in C:\ProgramData\WebTAK Server).

CONNECT DEVICES
  Web interface -> Users -> create a user -> "QR / package"
  ATAK: Settings > Network > Server Connections > + > Scan QR
  iTAK: Settings > Network > Servers > + > Scan QR
  WinTAK: download the connection package (.zip) and drag it onto the map.

VIDEO
  The video server (mediamtx.exe, MediaMTX) is included and starts by itself.
  Drones / OBS send to rtmp://<this-PC>:1935/<name>?user=<user>&pass=<password>,
  ATAK finds the streams under Video. Keep mediamtx.exe next to webtak-server.exe.

FORGOT THE ADMIN PASSWORD?
  Stop the server, then in a command prompt (as administrator) in this folder:
  webtak-server.exe reset-password admin

More: https://github.com/fredy060795/5040-WebTAK_Server
