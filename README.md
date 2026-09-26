# cert-enrolment

Device certificate enrolment for a home or small-office Wi-Fi network that
uses 802.1X (EAP-TLS).

`cert-enrolment` lets a member of an LDAP enrollers group register a device
and download everything that device needs to join the trusted network: a
device certificate from a [step-ca](https://smallstep.com/docs/step-ca/)
certificate authority, the Root CA, and the Wi-Fi configuration. Devices then
renew their certificates by themselves, and deleting a device revokes its
certificates.

It is one small Rust binary with two roles, run as two containers from the
same image behind a TLS-terminating reverse proxy:

* **portal** — the web pages people use to sign in, enrol devices and
  manage them. It holds no signing keys and no LDAP service account.
* **ra** — the registration authority. It owns device records, obtains
  every device certificate from step-ca, records each one, and revokes them
  when a device is deleted. It alone holds the LDAP service account and the
  step-ca provisioner key.

Names used below are placeholders. Examples use the reserved
`example.home.arpa` domain; substitute your own.

## How it fits together

```text
 person's browser ──HTTPS──▶ proxy ──▶ portal ──API key──▶ RA ──LDAPS──▶ LDAP (devices, certificates)
      (join.<domain>)                    │                   │
                                         └──LDAPS (sign-in)  └──HTTPS──▶ step-ca  (sign, revoke)

 device script ──HTTPS──▶ proxy ──▶ RA   (ra.<domain>)
                  │         enrol: single-use enrolment code
                  │         renew: the device's current certificate, verified by the proxy
                  └─ client certificate optional; the proxy passes the result to the RA

 device ──EAP-TLS──▶ access point ──RADIUS──▶ FreeRADIUS ──▶ LDAP
```

Each part does its own job:

| Part | Job |
|---|---|
| LDAP | Who may enrol (enrollers group), which devices exist, their zone, whether they are enabled, and their certificates |
| Portal | Pages; asks the RA to act on behalf of the signed-in user |
| RA | Policy: checks LDAP, obtains certificates, records serials and expiry, revokes |
| step-ca | Issues and revokes certificates |
| FreeRADIUS | Enforces at connection time |
| Firewall | Enforces what each VLAN may reach; FreeRADIUS only assigns VLANs |

Devices never talk to step-ca, and no device private key ever leaves its
device.

## Networks

The design uses three Wi-Fi networks (SSIDs). Their names are a deployment
choice; they are referred to here by role.

| Role | Example name | Security | Who joins | VLAN |
|---|---|---|---|---|
| **Trusted** | `Home` | WPA3-Enterprise, EAP-TLS | Enrolled devices | Assigned per device by FreeRADIUS from `deviceZone` (for example `trusted`, `quarantine`) |
| **Onboarding** | `Home-Setup` | Enhanced Open (OWE), with a captive portal; never plain open | Devices being enrolled | A dedicated onboarding VLAN that can reach only DNS, the portal and the RA, never the internet |
| **IoT** | `Home-IoT` | WPA2/WPA3-Personal | Devices that cannot do 802.1X | A lower-trust IoT VLAN |

Why three and not one:

* An Enterprise network admits only devices that can already authenticate,
  so a device without a certificate cannot use it to fetch one. A second,
  password-based EAP method on the same network would work, but it would
  pass user passwords through FreeRADIUS and teach users to accept
  certificate prompts, so this design keeps the trusted network EAP-TLS
  only.
* Quarantine and future posture zones do not need their own network: they
  are VLANs chosen by FreeRADIUS on the trusted network.
* One network cannot mix Enterprise and password security, so IoT devices
  have their own.

## Onboarding

1. The device joins the onboarding network. The access point's captive
   portal sends it to `http://join.<domain>/` (the portal host name is a
   deployment choice).
2. That is the portal itself, served over **plain HTTP** so that a device
   which does not trust the Root CA yet can use it: the user signs in,
   registers the device and downloads its enrolment script, all in the
   captive-portal window or browser, with no separate step.
3. The enrolment script installs the Root CA, obtains the device
   certificate from the RA over HTTPS and adds a Wi-Fi profile for the
   trusted network, and the device moves to it.

The plain-HTTP portal is a second listener in the portal role
(`CERT_ENROLMENT_ONBOARDING_LISTEN`). It serves the same pages, with its
own sessions and its own cookies (`onboarding-session`,
`onboarding-login-csrf`: no `Secure`, since browsers refuse that over HTTP,
but still `HttpOnly` and `SameSite=Strict`). A session started on one
listener is never accepted on the other. Unknown `GET` paths redirect to
`/`, since captive portals add their own paths and parameters.

Captive-portal configuration: point the onboarding network's external portal
at the HTTP address, and allow the portal and RA host names before
authorisation. Nothing ever needs to be authorised to reach the internet.
Serve the plain-HTTP portal only to the onboarding VLAN; other networks use
HTTPS.

**Accepted risk.** Sign-in, the enrolment code and the script travel over
plain HTTP on the onboarding network.

* Passive capture of the password is prevented by requiring **Enhanced
  Open (OWE)**, which encrypts the radio link per client. The onboarding
  network must never be plain open.
* OWE does not authenticate the access point, so someone in radio range
  could run a fake onboarding network, collect the password and hand out a
  script of their own. Delivering the Root CA over HTTP, then switching to
  HTTPS, would not prevent that either: a fake network can hand out its own
  Root CA. This design accepts the risk for a home network where only
  trusted people enrol devices, in range of the home.

Deployments that want more can give the portal a publicly trusted
certificate (for example Let's Encrypt with DNS-01 on a domain they own; no
public address records are needed) and send the captive portal to HTTPS
instead, or pre-install the Root CA on each device out of band.

## Device identity

* Every device is `<name>.<device domain>`, for example
  `ed-laptop.device.example.home.arpa`: a single label under the device
  domain. This name is the certificate Common Name and the LDAP `deviceId`.
  It is never published in DNS.
* Device entries use object classes `device` and `managedDevice` in a
  devices container such as `ou=Devices,dc=example,dc=home,dc=arpa`:
  `deviceId`, `description`, `deviceType`, `deviceZone`, `deviceDisabled`,
  `owner` (the enroller who registered it) and `deviceCertificate`.
* `deviceCertificate` holds one value per certificate the RA obtained for
  the device: its serial in hex and its expiry, `<serial> <YYYYMMDDHHMMSSZ>`.
  Values are removed once their certificate has expired.

## Enrolment and renewal

1. A member of the enrollers group signs in to the portal with their LDAP
   credentials and registers a device (name, type, zone). The RA creates
   its LDAP entry.
2. On the device itself they download the enrolment script for its
   platform. For each download the RA issues a random enrolment code for
   that device, valid for ten minutes and usable once, and the portal writes
   it into the script.
3. The script creates a key on the device and sends a certificate request
   with the code to the RA (`POST /v1/enrol`). The RA checks the code and
   that the device is registered and enabled, has step-ca sign the request
   with a token naming only that device, records the certificate, and
   returns it.
4. Once two thirds of the certificate's lifetime has passed, the device
   creates a new key and sends a certificate request to the RA
   (`POST /v1/renew`), presenting its current certificate. The proxy
   verifies it against the CA chain; the RA then requires that the device is
   still registered and enabled, and that the certificate presented is the
   **newest** one recorded for it. A copy of an older certificate cannot
   renew, and nor can certificates from before a device was deleted and
   registered again.

| Platform | Delivered as | Key storage | Renewal |
|---|---|---|---|
| Windows 11 | PowerShell script, run once as administrator | TPM (Microsoft Platform Crypto Provider), Local Computer store, not exportable | Scheduled task (daily and at start-up) |
| Linux | Shell script, run once as root | File, root-only | systemd timer (daily) |
| iOS | `.mobileconfig` profile (Root CA + SCEP + Wi-Fi) — planned | Keychain | Re-download from the portal before expiry, until an MDM is used |

The Wi-Fi configuration on every platform is for the trusted network, trusts
only the Root CA, validates the RADIUS server name, and uses TLS 1.3. Linux
supplicants (wpa_supplicant 2.10) disable EAP TLS 1.3 by default, so the
Linux script enables it explicitly. Windows 11 22H2 and later use TLS 1.3 for
EAP-TLS by default.

### Enrolment scripts

* Downloaded from the Enrol step (`POST /enrol/download`). Disabled devices
  are refused.
* Every value written into a script has a restricted format (checked at
  start-up or registration) and is also quoted for the script language.
  Scripts are ASCII; Windows scripts use CRLF and Linux scripts LF.
* Before changing anything, the scripts check that the RA's host name
  resolves. A service that cannot be reached is reported with the code
  unused, so the script can simply be run again.
* **Windows** (`enrol-<name>.ps1`, Windows PowerShell 5.1 or later, run
  elevated): adds the Root CA to Local Computer › Trusted Root CAs; creates
  a P-256 key in the TPM with `certreq` (`-AllowSoftwareKey` falls back to a
  non-exportable software key); installs the certificate and its
  intermediate; adds a WPA3-Enterprise EAP-TLS profile (machine
  authentication, server name and Root CA pinned) with
  `netsh wlan add profile ... user=all` (`-SkipWifi` skips it); writes
  `%ProgramData%\cert-enrolment\renew.ps1` (SYSTEM and Administrators only)
  and registers the scheduled task `cert-enrolment renewal`. Pending
  requests and keys left by failed attempts are removed.
* **Linux** (`enrol-<name>.sh`, POSIX sh with curl, OpenSSL and GNU
  `date`, run as root): keeps its files in `/etc/cert-enrolment`, installs
  `/usr/local/libexec/cert-enrolment-renew`, adds a NetworkManager profile
  when `nmcli` is present (otherwise prints a wpa_supplicant block), and a
  systemd timer when systemd is present (otherwise asks for a cron entry).
* A device that stays off past expiry cannot renew and must be enrolled
  again.
* The Devices page shows when each device's newest certificate expires,
  as the RA recorded it. Devices renew ten days before expiry and try
  daily, so a certificate within seven days of expiry is flagged as
  renewal overdue, and an expired one as needing enrolment again.

## Certificates

* 30-day lifetime on every platform; clientAuth only. FreeRADIUS rejects
  certificates that also carry serverAuth, which excludes service
  certificates from the same CA.
* step-ca has a JWK provisioner whose **public** key is in its
  configuration; the RA holds the **private** key and signs single-use
  tokens with it: sign tokens name one device, revoke tokens one serial.
  Nothing else needs the key, so it is not stored encrypted in the CA
  configuration. Keep it stable: certificates record which provisioner
  issued them.
* step-ca's own renewal is **disabled** for this provisioner, so every
  certificate goes through the RA and every serial is recorded.
* The provisioner's certificate template issues clientAuth only; the CA
  policy must allow the device domain (one label deep, as step-ca wildcards
  match a single label).
* **Disable** a device: FreeRADIUS refuses it at its next association, and
  the RA refuses to renew its certificates. Enabling it again restores both.
* **Delete** a device: the RA first disables it, then revokes every
  unexpired certificate recorded for it in step-ca (passive revocation),
  then removes its entry. If a revocation fails, the device stays disabled
  and deleting it again resumes.

## Portal

* **Enrol a device** (`/enrol`): a stepped flow, Sign in → Device → Enrol
  → Connect. The Enrol step (`/enrol/device`) offers the device's script.
* **Devices** (`/devices`): every registered device, with enrol, disable,
  enable and delete. Deleting asks for confirmation on a separate page (the
  Content Security Policy allows no script, so there is no browser dialog).
* Any enroller can act on any device. Every change is logged by the RA with
  the enroller and device.
* Pages use IBM Plex Mono (SIL Open Font License, see
  `src/portal/assets/fonts/LICENSE.txt`) and a halftone background, all
  embedded in the binary. JavaScript is optional: it preselects the device
  type from the browser and shows the matching illustration and naming tip.
  Browsers do not expose the computer's name, so the name is typed.

### Sign-in and sessions

* Users sign in by binding to LDAP as themselves; enrollers-group
  membership is then read over the same connection. Account lockout is left
  to the directory's password policy.
* Empty passwords are refused before contacting LDAP, because an empty
  password is an anonymous bind, which LDAP accepts.
* User names are restricted to `[a-z0-9._-]`, and are escaped as well
  before use in a DN or filter.
* Sessions are random 256-bit tokens held in memory, so signing out really
  ends a session. A restart signs everyone out. Sessions expire after
  `CERT_ENROLMENT_SESSION_MINUTES` of inactivity.
* Cookies are `__Host-` prefixed, `Secure`, `HttpOnly` and
  `SameSite=Strict`. Every form carries a CSRF token; the sign-in form uses
  a double-submit cookie.
* Responses carry a restrictive Content Security Policy, `nosniff` and
  `no-referrer`; pages are `no-store`. All page values are HTML-escaped.

## RA API

All bodies are JSON. Errors are `{"error": "<message for people>"}`.

For the portal (`Authorization: Bearer <API key>`, and `X-Actor: <user>`
naming the signed-in user):

| Method and path | Does |
|---|---|
| `GET /api/devices` | Lists devices |
| `POST /api/devices` | Registers a device: `label`, `description`, `platform`, `zone` |
| `GET /api/devices/<label>` | One device |
| `POST /api/devices/<label>/disable`, `/enable` | Disables or enables it |
| `DELETE /api/devices/<label>` | Revokes its certificates and deletes it |
| `POST /api/devices/<label>/enrolment-code` | Issues an enrolment code |

For devices, through the proxy:

| Method and path | Authorised by | Body |
|---|---|---|
| `POST /v1/enrol` | Enrolment code | `code`, `csr` |
| `POST /v1/renew` | Current certificate (`X-Client-Verify: SUCCESS` and `X-Client-Cert` from the proxy) | `csr` |

Both answer `{"crt": "<certificate>", "ca": "<intermediate>"}`.
`GET /healthz` answers `ok` on both roles.

The RA trusts `X-Client-*` headers, so it must be reachable only through the
proxy (for example published on loopback), and the proxy must set those
headers itself, replacing any a client sends.

## Configuration

Both roles:

| Variable | Default | Meaning |
|---|---|---|
| `CERT_ENROLMENT_ROLE` | `portal` | `portal` or `ra` |
| `CERT_ENROLMENT_LISTEN` | `0.0.0.0:8080` | Address and port to listen on (plain HTTP) |
| `CERT_ENROLMENT_LDAP_URL` | required | LDAP server; must be `ldaps://` |
| `CERT_ENROLMENT_LDAP_PEOPLE_DN` | required | Users are `uid=<name>,<this DN>` |
| `CERT_ENROLMENT_DEVICE_DOMAIN` | required | Device identities are `<name>.<this domain>` |
| `CERT_ENROLMENT_DEVICE_ZONES` | required | Comma-separated zones offered at registration; the first is the default. Must match the zones FreeRADIUS maps to VLANs |
| `CERT_ENROLMENT_RA_API_KEY_FILE` | required | File holding the key the portal presents to the RA, at least 32 characters |
| `CERT_ENROLMENT_ROOT_CA_FILE` | `SSL_CERT_FILE` | PEM file with the one Root CA certificate: given to devices (portal) and trusted for step-ca (RA) |
| `SSL_CERT_FILE` | none | PEM file of CAs trusted for LDAPS. The image has no other trust store |

Portal only:

| Variable | Default | Meaning |
|---|---|---|
| `CERT_ENROLMENT_LDAP_ENROLLERS_GROUP_DN` | required | `posixGroup` whose `memberUid` values may sign in |
| `CERT_ENROLMENT_RA_URL` | required | The RA's API as the portal reaches it, e.g. `http://cert-enrolment-ra:8080` |
| `CERT_ENROLMENT_RA_PUBLIC_URL` | required | The RA as devices reach it, `https://host[:port]`; written into scripts |
| `CERT_ENROLMENT_WIFI_SSID` | required | Trusted network the scripts configure; 1 to 32 printable ASCII characters |
| `CERT_ENROLMENT_RADIUS_SERVER_NAME` | required | DNS name in the RADIUS server certificate, which devices validate |
| `CERT_ENROLMENT_SESSION_MINUTES` | `30` | Idle time before a session expires |
| `CERT_ENROLMENT_ONBOARDING_LISTEN` | none | Address and port to also serve the portal on for plain HTTP from the onboarding network, e.g. `0.0.0.0:8081`; unset serves none |

RA only:

| Variable | Default | Meaning |
|---|---|---|
| `CERT_ENROLMENT_LDAP_BIND_DN` | required | Service account for device entries |
| `CERT_ENROLMENT_LDAP_BIND_PASSWORD_FILE` | required | File holding its password |
| `CERT_ENROLMENT_LDAP_DEVICES_DN` | required | Container of device entries |
| `CERT_ENROLMENT_CA_URL` | required | step-ca base URL, `https://host[:port]` |
| `CERT_ENROLMENT_PROVISIONER` | required | Name of the step-ca JWK provisioner |
| `CERT_ENROLMENT_PROVISIONER_KEY_FILE` | required | File holding its private key as an EC P-256 JWK. Checked at start-up |

## LDAP requirements

* A posixGroup of enrollers; its `memberUid` values may sign in.
* A service account for the RA that can create, modify and delete entries
  in the devices container, and nothing else.
* The `managedDevice` auxiliary object class with `deviceId`, `deviceType`,
  `deviceZone`, `deviceDisabled` and `deviceCertificate` (multi-valued).
* LDAPS, with a server certificate that chains to the CA in
  `SSL_CERT_FILE`.

## Deployment

Run the image twice, as the portal and as the RA, on a private container
network so the portal reaches the RA by name. Both listen on plain HTTP as
an unprivileged user (UID 65532); publish them on loopback only. A reverse
proxy terminates TLS:

* for the portal host name (e.g. `join.<domain>`), plainly;
* on plain HTTP for the portal host name, to the onboarding listener, if
  used, and only for the onboarding network;
* for the RA host name (e.g. `ra.<domain>`), with optional client
  certificates verified against the Root and Intermediate CA, passing
  `X-Client-Verify` (`$ssl_client_verify` in NGINX) and `X-Client-Cert`
  (`$ssl_client_escaped_cert`).

Give only the RA the LDAP service account and the provisioner key; give both
the API key. A reference deployment, using rootless Podman, Quadlet, NGINX
and Ansible, is the `cert-enrolment` role in
[elaverick/homelab](https://github.com/elaverick/homelab).

## Code layout

```text
src/
├── main.rs      chooses the role
├── shared/      device model and validation, HTTP helpers, settings, random tokens, times
├── portal/      pages, sessions, sign-in, the RA client, enrolment script templates
└── ra/          API, device records, certificates, enrolment codes, step-ca client, tokens
```

## Dependencies

| Crate | Purpose |
|---|---|
| `tiny_http` | HTTP server |
| `ldap3` | LDAP (sync API, rustls with ring; no OpenSSL) |
| `p256`, `base64`, `serde_json` | Signing step-ca tokens (ES256 JWS); JSON |
| `ureq` | HTTP client: RA to step-ca (rustls), portal to RA |
| `x509-parser` | Reading serials, names and expiry from certificates (RA) |

Random tokens come from `/dev/urandom`.

## Build

```
cargo build --release
```

or build the image:

```
podman build -t cert-enrolment -f Containerfile .
```

`build-cert-enrolment.yaml` builds `./Containerfile` and pushes to
`ghcr.io/<owner>/cert-enrolment` (`latest` on `main`, semver tags on
`v*.*.*`), and `secret-scan.yaml` runs Gitleaks on every push and pull
request.

## Status

* [x] Service skeleton, container image and CI
* [x] LDAP sign-in restricted to the enrollers group
* [x] Device registration, disable, enable and delete
* [x] Reference deployment (homelab role, NGINX sites and certificates)
* [x] Linux enrolment script (tested end to end, including renewal)
* [x] Windows enrolment script (a real Windows 11 device enrolled: TPM key, certificate, Wi-Fi profile, renewal task)
* [x] Portal and RA roles; renewal through the RA; revocation in step-ca on delete (tested end to end against step-ca 0.30.2)
* [x] Onboarding: the portal over plain HTTP as the captive portal
* [x] Certificate expiry on the Devices page
* [ ] Captive-portal setup on the access points
* [ ] step-ca SCEP provisioner and challenge webhook
* [ ] iOS enrolment profile
