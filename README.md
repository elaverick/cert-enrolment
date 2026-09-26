# cert-enrolment

Device certificate enrolment for a home or small-office Wi-Fi network that
uses 802.1X (EAP-TLS).

`cert-enrolment` lets a member of an LDAP enrollers group register a device
and download everything that device needs to join the trusted network: a
device certificate from a [step-ca](https://smallstep.com/docs/step-ca/)
certificate authority, the Root CA, and the Wi-Fi configuration. It is a
single small Rust binary, run as a container behind a TLS-terminating
reverse proxy.

Names used below are placeholders. Examples use the reserved
`example.home.arpa` domain; substitute your own.

## How it fits together

```text
 browser on the device ──HTTPS──▶ reverse proxy ──HTTP──▶ cert-enrolment ──LDAPS──▶ LDAP
                                                             │           (devices,
                                                             │            enrollers group)
                                              signs single-use tokens
                                                             │
 device ──── CSR + token (Windows, Linux) ────────────────▶ step-ca
 device ──── SCEP (iOS) ──────────────────────────────────▶ step-ca ──webhook──▶ cert-enrolment
                                                                          (challenge check)

 device ──── EAP-TLS ──▶ access point ──RADIUS──▶ FreeRADIUS ──▶ LDAP
```

`cert-enrolment` never handles a device's private key and never calls
step-ca itself. Its only outbound connection is to LDAP.

The companion pieces are expected to be configured as follows:

* **step-ca** issues device certificates with clientAuth only, for names
  under the device domain.
* **FreeRADIUS** accepts EAP-TLS only. It accepts a device if its
  certificate chains to the Root CA, carries clientAuth and not serverAuth,
  has a Common Name that is a single label under the device domain, and
  matches an enabled device entry in LDAP. The entry's `deviceZone`
  selects the VLAN returned to the access point.
* **The firewall** enforces what each VLAN may reach. FreeRADIUS only
  assigns VLANs.

## Networks

The design uses three Wi-Fi networks (SSIDs). Their names are a deployment
choice; they are referred to here by role.

| Role | Example name | Security | Who joins | VLAN |
|---|---|---|---|---|
| **Trusted** | `Home` | WPA3-Enterprise, EAP-TLS | Enrolled devices | Assigned per device by FreeRADIUS from `deviceZone` (for example `trusted`, `quarantine`) |
| **Onboarding** | `Home-Setup` | Open, preferably Enhanced Open (OWE), with a captive portal | Devices being enrolled | A dedicated onboarding VLAN that can reach only DNS, `cert-enrolment` and step-ca, never the internet |
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
2. That first page is served over **plain HTTP**, only on the onboarding
   VLAN. Its sole purpose is to deliver the Root CA in the form the device
   needs, with the Root CA fingerprint shown for comparison:
   * **Windows:** the certificate, with install instructions.
   * **iPhone / iPad:** a configuration profile containing the Root CA.
     Captive-portal windows on iOS cannot install profiles, so the page
     asks the user to continue in Safari. After installing, full trust is
     enabled under Settings › General › About › Certificate Trust Settings.
   * **Linux:** a one-line install.
3. The user continues to `https://join.<domain>/`, now trusted. Sign-in,
   registration and the enrolment download all happen over HTTPS.
4. The enrolment material installs the device certificate and a Wi-Fi
   profile for the trusted network, and the device moves to it.

Captive-portal configuration: point the onboarding network's external portal
at the HTTP address, and allow the portal host and step-ca before
authorisation. Nothing ever needs to be authorised to reach the internet.

**Accepted risk.** The Root CA is delivered over plain HTTP, and the
onboarding network is open, so someone in radio range could run a fake
onboarding network that serves a different Root CA. This design accepts that
risk for a home network where only trusted people enrol devices. The shown
fingerprint allows a manual check. Deployments that want more can instead
give the portal a publicly trusted certificate (for example Let's Encrypt
with DNS-01 on a domain they own; no public address records are needed), or
pre-install the Root CA on each device out of band.

## Device identity

* Every device is `<name>.<device domain>`, for example
  `ed-laptop.device.example.home.arpa`: a single label under the device
  domain. This name is the certificate Common Name and the LDAP `deviceId`.
  It is never published in DNS.
* Device entries use object classes `device` and `managedDevice`
  (`deviceId`, `deviceType`, `deviceZone`, `deviceDisabled`) in a devices
  container such as `ou=Devices,dc=example,dc=home,dc=arpa`.

## Enrolment flow

1. A member of the enrollers group signs in with their LDAP credentials.
2. They register a device (name, type, zone), which creates its LDAP entry.
3. On the device itself they download the enrolment material for its
   platform. Each download embeds a credential that is single-use, bound
   to that device name, and valid for about ten minutes.

| Platform | Delivered as | Key storage | Issuance | Renewal |
|---|---|---|---|---|
| Windows 11 | PowerShell script, run once as administrator | TPM (Microsoft Platform Crypto Provider), machine store | step-ca JWK provisioner, single-use token | Scheduled task, mTLS renewal against step-ca |
| Linux | Shell script | File, root-only | step-ca JWK provisioner, single-use token | systemd timer, `step ca renew` |
| iOS | `.mobileconfig` profile (Root CA + SCEP + Wi-Fi) | Keychain | step-ca SCEP provisioner, challenge checked by `cert-enrolment` webhook | Re-download from the portal before expiry, until an MDM is used |

The Wi-Fi configuration on every platform is for the trusted network, trusts
only the Root CA, validates the RADIUS server name, and uses TLS 1.3. Linux
supplicants (wpa_supplicant 2.10) disable EAP TLS 1.3 by default, so the
Linux script enables it explicitly.

## Enrolment tokens

* step-ca has a JWK provisioner whose **public** key is in its configuration;
  `cert-enrolment` holds the **private** key. Nothing else needs it, so the
  key is not stored encrypted in the CA configuration.
* Each token is an ES256 JWT for one device name (`sub` and `sans`), with a
  random `jti`, valid for ten minutes. step-ca records spent tokens, so each
  can be used once.
* The provisioner's certificate template issues clientAuth only; the CA
  policy must allow the device domain (one label deep, as step-ca
  wildcards match a single label).
* Keep the provisioner key stable. Certificates record which provisioner
  issued them, and renewals are checked against it; a new key means every
  device must enrol again.

## Certificates

* 30-day lifetime on every platform.
* clientAuth only. FreeRADIUS rejects certificates that also carry
  serverAuth, which excludes service certificates from the same CA.
* A Windows or Linux device that stays off past expiry cannot renew and
  must be enrolled again.
* Revocation: set `deviceDisabled` in LDAP (effective at the next
  association). Revoking in step-ca additionally blocks renewal.

## Pages

* **Enrol a device** (`/enrol`): a stepped flow, Sign in → Device → Enrol
  → Connect. The Device step registers the device; the Enrol step
  (`/enrol/device`) will deliver the enrolment material.
* **Devices** (`/devices`): every registered device, with disable, enable
  and delete.
* Pages use IBM Plex Mono (SIL Open Font License, see
  `src/assets/fonts/LICENSE.txt`) and a halftone background, all embedded
  in the binary. The Content Security Policy allows only same-origin
  scripts, styles, fonts and images.
* JavaScript is optional. When present it preselects the device type from
  the browser and shows the matching illustration and naming tip. Browsers
  do not expose the computer's name, so the name is typed.

## Device registration

* A signed-in enroller enters a device name (one DNS label, lowercased),
  an optional description (up to 64 characters, stored in `description`),
  a device type (Windows, Linux or iPhone / iPad) and a network zone from
  `CERT_ENROLMENT_DEVICE_ZONES`.
* The service account creates `cn=<name>.<device domain>,<devices DN>`
  with object classes `device` and `managedDevice`: `deviceId` (same as
  the CN), `description` (if given), `deviceType` (platform), `deviceZone`,
  `deviceDisabled: FALSE`, and `owner` set to the enroller's DN for
  auditing.
* Names that already exist are refused. All enrollers see every device.
* Registrations are logged with the enroller, device, platform and zone.

## Disabling and deleting devices

* Any enroller can disable, enable or delete any device from the list.
* Disable sets `deviceDisabled: TRUE`; FreeRADIUS then rejects the device
  at its next association. Enable sets it back to `FALSE`.
* Delete removes the LDAP entry after a confirmation page (the Content
  Security Policy allows no script, so there is no browser dialog).
* Each change is logged with the enroller and device.
* Certificates are not yet revoked. A disabled or deleted device's
  certificate stays valid until it expires, but FreeRADIUS refuses it.

## Sign-in and sessions

* Users sign in by binding to LDAP as themselves; enrollers-group
  membership is then read over the same connection. Sign-in uses no
  service account. Account lockout is left to the directory's password
  policy.
* Empty passwords are refused before contacting LDAP, because an empty
  password is an anonymous bind, which LDAP accepts.
* User names are restricted to `[a-z0-9._-]`, and are escaped as well
  before use in a DN or filter.
* Sessions are random 256-bit tokens held in memory, so signing out really
  ends a session. A restart signs everyone out. Sessions expire after
  `CERT_ENROLMENT_SESSION_MINUTES` of inactivity.
* Cookies are `__Host-` prefixed, `Secure`, `HttpOnly` and
  `SameSite=Strict`. Every form carries a CSRF token; the sign-in form
  uses a double-submit cookie.
* Responses carry a restrictive Content Security Policy, `nosniff` and
  `no-referrer`; pages are `no-store`. All page values are HTML-escaped.

## LDAP requirements

* A posixGroup of enrollers; its `memberUid` values may sign in.
* A service account that can create, modify and delete entries in the
  devices container, and nothing else.
* The `managedDevice` auxiliary object class (`deviceId`, `deviceType`,
  `deviceZone`, `deviceDisabled`).
* LDAPS, with a server certificate that chains to the CA in
  `SSL_CERT_FILE`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CERT_ENROLMENT_LISTEN` | `0.0.0.0:8080` | Address and port to listen on |
| `CERT_ENROLMENT_LDAP_URL` | required | LDAP server; must be `ldaps://` |
| `CERT_ENROLMENT_LDAP_PEOPLE_DN` | required | Users sign in as `uid=<name>,<this DN>` |
| `CERT_ENROLMENT_LDAP_ENROLLERS_GROUP_DN` | required | `posixGroup` whose `memberUid` values may sign in |
| `CERT_ENROLMENT_LDAP_BIND_DN` | required | Service account for reading and writing device entries |
| `CERT_ENROLMENT_LDAP_BIND_PASSWORD_FILE` | required | File holding the service account password (for example a container secret) |
| `CERT_ENROLMENT_LDAP_DEVICES_DN` | required | Container of device entries |
| `CERT_ENROLMENT_DEVICE_DOMAIN` | required | Device identities are `<name>.<this domain>` |
| `CERT_ENROLMENT_DEVICE_ZONES` | required | Comma-separated zones offered at registration; the first is the default. Must match the zones FreeRADIUS maps to VLANs |
| `CERT_ENROLMENT_CA_URL` | required | step-ca base URL as devices reach it; must be `https://`. Tokens are issued for `<this URL>/1.0/sign` |
| `CERT_ENROLMENT_PROVISIONER` | required | Name of the step-ca JWK provisioner whose key signs enrolment tokens |
| `CERT_ENROLMENT_PROVISIONER_KEY_FILE` | required | File holding that provisioner's private key as an EC P-256 JWK (for example a container secret). Checked at start-up |
| `CERT_ENROLMENT_SESSION_MINUTES` | `30` | Idle time before a session expires |
| `SSL_CERT_FILE` | none | PEM file of CAs trusted for LDAPS. Set it to your Root CA; the image has no other trust store |

## Deployment

The image listens on plain HTTP and expects a reverse proxy to terminate TLS
for the portal host name. It runs as an unprivileged user (UID 65532) and
needs only outbound LDAPS.

A reference deployment, using rootless Podman, Quadlet, NGINX and Ansible,
is the `cert-enrolment` role in
[elaverick/homelab](https://github.com/elaverick/homelab).

## Dependencies

Agreed set, each added with the feature that needs it:

| Crate | Purpose |
|---|---|
| `tiny_http` | HTTP server |
| `ldap3` | LDAP sign-in and device entries (sync API, rustls with ring; no OpenSSL) |
| `p256`, `ecdsa`, `base64`, `serde_json` | Signing step-ca single-use tokens (ES256 JWS) |

`hmac` and `sha2` were originally planned for signed session cookies.
Sessions are held in memory instead, so they are not needed. Random tokens
come from `/dev/urandom`.

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
* [x] Device registration
* [x] Disable, enable and delete devices
* [x] Reference deployment (homelab role, NGINX site and certificate)
* [x] step-ca JWK provisioner and single-use token signing
* [ ] Windows enrolment script
* [ ] Linux enrolment script
* [ ] Onboarding: HTTP bootstrap page with the Root CA, and captive-portal setup
* [ ] step-ca SCEP provisioner and challenge webhook
* [ ] iOS enrolment profile
* [ ] Revoke the certificate in step-ca when a device is deleted, so it cannot renew
* [ ] Expiry view for devices that renew manually (iOS)
