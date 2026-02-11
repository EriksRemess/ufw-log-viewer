# UFW Log Viewer

A small terminal app for browsing and filtering UFW logs.

## Build

```bash
make build
```

## Install

```bash
sudo make install
```

## Run

```bash
ufw-log-viewer
```

Optional log path:

```bash
ufw-log-viewer /path/to/ufw.log
```

If you do not pass a path, the app checks logs in this order:
1. `/var/log/ufw-firewall.log`
2. `/var/log/ufw.log`
3. `/var/log/kern.log`

Quick CLI:

```bash
ufw-log-viewer --help
ufw-log-viewer --version
```

## Controls

- `F1..F6`: edit filters
- `Shift+F1..F6`: clear one filter
- `a`: pause or resume live updates
- `,` / `.`: switch interface
- `Ctrl+C`: copy the selected row
- `Ctrl+I`: copy the selected source IP
- `Left` / `Right`: scroll long log-entry text
- On wider screens, service descriptions are shown

## Service Data

Service names and descriptions come from IANA and are embedded into the binary.

To refresh the local CSV snapshot:

```bash
./scripts/update_iana_services.sh
```

## Debian Package

Prebuilt `.deb` packages are also published in GitHub Releases.

```bash
make deb
```
