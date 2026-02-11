# UFW Log Viewer

Simple Rust TUI for reading and filtering UFW logs.

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

Default log lookup order:
1. `/var/log/ufw-firewall.log`
2. `/var/log/ufw.log`
3. `/var/log/kern.log`

## Controls

- `F1..F6`: edit filters
- `Shift+F1..F6`: clear one filter
- `a`: pause/resume live updates
- `,` / `.`: change interface
- `Ctrl+C`: copy selected row
- `Ctrl+I`: copy selected source IP
- `Left` / `Right`: scroll selected log entry text

## Debian Package

```bash
make deb
```
