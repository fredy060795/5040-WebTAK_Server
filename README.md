# WebTAK Server

**Your own TAK server in one file.** Runs on Windows, Raspberry Pi, Linux and macOS – no database, no Docker,
no nginx, no command line knowledge needed. Works with **ATAK, iTAK and WinTAK** like OpenTAKServer (OTS), and
several servers can be **linked together (federation)** so all their devices see each other.

```
 ATAK / iTAK / WinTAK ──▶ WebTAK Server A ◀══ federation ══▶ WebTAK Server B ◀── ATAK / iTAK / WinTAK
                               ▲                                   ║
                               ║            federation             ║
                               ╚════════════ Server C ═════════════╝
```

| | OpenTAKServer (see `OTS Anleitung Webseite.pdf`) | WebTAK Server |
|---|---|---|
| Install | Ubuntu/Pi OS, SSH, installer script, PostgreSQL, RabbitMQ, nginx, certbot … | download, double-click (Windows) or one command (Pi) |
| Runs on | Linux | Windows, Raspberry Pi (all models), Linux, macOS, Docker |
| Setup | default password `administrator`/`password`, edit nginx files | web wizard: set the admin password, done |
| Connect devices | QR code / data package | QR code (ATAK + iTAK) / data package (WinTAK) |
| Link servers | – | invite code, both directions, chains and rings |

---

## Install

### Windows

1. Download **`WebTAK-Server-Windows-amd64.zip`** from [Releases](https://github.com/fredy060795/5040-WebTAK_Server/releases/latest) and unzip it.
2. **Try it:** double-click `webtak-server.exe`. Click *Allow* when Windows asks about network access.
   The browser opens the setup page by itself.
3. **Install for good:** double-click `Install.bat` (confirm the administrator question). The server then runs in
   the background, starts with Windows and the firewall is opened. Data of the test run is taken over.

Web interface on the server PC: <http://localhost:8080/> · from other devices: `https://<PC-IP>:8443/`

### Raspberry Pi / Linux

Open a terminal (or SSH) and paste:

```sh
curl -fsSL https://raw.githubusercontent.com/fredy060795/5040-WebTAK_Server/main/install/install.sh | sudo sh
```

That is all – the right program for the Pi model is downloaded, installed as a service that starts automatically,
and the firewall (ufw) is opened if active. Run the same command again to update.
Then open `https://<pi-ip>:8443/` in a browser (accept the certificate warning once: *Advanced → Continue*).

Works on every Raspberry Pi (Zero, 1–5, 32- and 64-bit OS), Ubuntu, Debian and other Linux systems with systemd.

### Docker

```sh
docker compose up -d
```

Then open `https://<host>:8443/` and set the server address under *Settings* (inside Docker the server cannot see the host's IP).

### Without installing (any system)

Download the file for your system from Releases and start it: `./webtak-server-linux-arm64`. Data is kept in a
folder `takdata` next to the program.

---

## First steps

1. **Setup wizard** – server name, admin password, optionally the address devices use (DNS name, DuckDNS,
   ZeroTier or Tailscale IP). Leave it empty for the local network address.
2. **Users** – create one user per person (password is generated if you leave it empty). Groups decide who sees whom.
3. **Connect devices** – choose the user → QR codes:
   - **ATAK:** *Settings → Network → Server Connections → ＋ → Scan QR* – everything is set up automatically
     (certificate enrollment, like with OTS).
   - **iTAK:** *Settings → Network → Servers → ＋ → Scan QR*, then log in with the user name and the shown password.
   - **WinTAK** (or ATAK without QR): *Download connection package* and drag the zip onto the map / import it.

Users can also log in to the web interface themselves and get the QR code for their own device under *My device*.

## Federation – linking servers

On server **A**: *Federation → Create invite code* → send the code to the admin of server **B**.
On server **B**: *Federation → Join with a code* → paste → *Link servers*. Done – the devices of A and B see each
other: positions, markers, drawings, chat (also direct messages) and data packages, in **both directions**.

- Only **B needs to reach A** (A's federation port 9000). B may sit behind a router or on a mobile connection – the one
  connection carries the data both ways. Reconnects happen automatically.
- **Chains and rings** work (A–B–C, or A–B–C–A): data is passed on with loop protection, nothing arrives twice.
  Can be switched off per link (*Edit → pass on data of further linked servers*).
- Per link you choose **which groups** are shared; a link can be switched off or removed on either side.
- Security: the invite contains a one-time token and the fingerprint of A's certificate authority. Both servers pin
  each other's certificates and agree on a secret for later reconnects; all traffic is TLS encrypted.
- The invite code contains all addresses of A. If B must use another address (DNS name, ZeroTier IP), enter it in
  the *Address* field when joining.

## Ports

| Port | Use |
|---|---|
| 8089/tcp | TAK devices, SSL with client certificate (recommended) |
| 8088/tcp | TAK devices, unencrypted without login (can be switched off) |
| 8446/tcp | certificate enrollment (QR code setup) |
| 8443/tcp | web interface and Marti API (data packages) over HTTPS |
| 8080/tcp | Marti API over HTTP; web interface only from the server computer itself |
| 9000/tcp | federation |

All ports can be changed with command line options (`webtak-server -help`). For access from the internet, forward
these ports in your router, or use **ZeroTier/Tailscale** (no port forwarding, as in the OTS guide).

## Compatibility

- **ATAK, iTAK, WinTAK** and other CoT clients: TCP and SSL streaming (CoT XML), certificate
  enrollment (`/Marti/api/tls/…`, QR `tak://com.atakmap.app/enroll`), data packages (`/Marti/sync/…`),
  contacts, groups, device profiles, video feed list (`/Marti/vcm`), ping/pong, latest positions for new devices.
- **Groups like OTS / TAK Server:** IN = may send into the group, OUT = receives from it; `__ANON__` is the default group.
- **OTS web API** (`/api/login`, `/api/user/*`, `/api/users`, `/api/groups`, `/api/eud`, `/api/atak_qr_string`,
  `/api/truststore`, `/api/profiles`, `/api/missions`): tools built for OpenTAKServer work unchanged. Tested with
  **WebTAK** (port 5036) – enter `https://<server>:8443` as OTS address with an admin login and allow the
  self-signed certificate.
- **Not included** (compared to OTS): media server (MediaMTX – use the WebTAK camera streams or a separate
  MediaMTX; feeds can be listed under *Video*), Meshtastic, Mumble, the full Data Sync / mission API, TAK protocol
  version 1 (protobuf – devices automatically stay on XML). Federation is between WebTAK Servers (own protocol);
  linking with an official TAK Server federation is not supported.

## Good to know

- **Backup:** copy the data folder (Windows: `C:\ProgramData\WebTAK Server`, Pi/Linux: `/var/lib/webtak-server`,
  portable: `takdata`). It contains users, certificates, links and data packages.
- **Forgot the admin password:** stop the server, then `webtak-server reset-password admin`
  (Pi: `sudo systemctl stop webtak-server && sudo -u webtak webtak-server reset-password -data /var/lib/webtak-server admin && sudo systemctl start webtak-server`).
- **Changing IP address:** the server certificate is renewed automatically when the computer gets a new address.
- **Own certificate** (e.g. Let's Encrypt for the web interface): *Settings → Own certificate*.
- **Logs:** web interface → *Log*; Pi: `sudo journalctl -u webtak-server -f`; file `server.log` in the data folder.
- Deleting or blocking a user revokes the certificates and disconnects the devices immediately.

## Build from source

```sh
go test ./...
go build -o webtak-server .                                    # this computer
GOOS=windows GOARCH=amd64 go build -o webtak-server.exe .       # Windows
GOOS=linux GOARCH=arm GOARM=6 go build -o webtak-server-pi .    # 32-bit Raspberry Pi
```

Releases are built by GitHub Actions: push a tag `v1.2.3` (or *Actions → Release → Run workflow*).

Code overview: `server.go` (ports, CoT connections) · `hub.go` (routing, groups) · `cot.go` (CoT parsing) ·
`marti.go` (device API, enrollment, data packages) · `federation.go` · `otsapi.go` (OTS-compatible API) ·
`admin.go` + `web/` (web interface) · `pki.go` (certificate authority) · `store.go` (data) · `service.go` (installers).
