SHELL := /bin/sh

CARGO ?= cargo
BINARY_NAME ?= ufw-log-viewer
OLD_BINARY_NAME ?= ufw-log-tui
PROFILE ?= release
PREFIX ?= /usr/local
DESTDIR ?=

BIN_PATH := target/$(PROFILE)/$(BINARY_NAME)
INSTALL_DIR := $(DESTDIR)$(PREFIX)/bin
INSTALL_PATH := $(INSTALL_DIR)/$(BINARY_NAME)
OLD_INSTALL_PATH := $(INSTALL_DIR)/$(OLD_BINARY_NAME)

.PHONY: build install uninstall deb clean

build:
	$(CARGO) build --profile "$(PROFILE)"

install: build
	install -d "$(INSTALL_DIR)"
	install -m 0755 "$(BIN_PATH)" "$(INSTALL_PATH)"
	rm -f "$(OLD_INSTALL_PATH)"

uninstall:
	rm -f "$(INSTALL_PATH)"
	rm -f "$(OLD_INSTALL_PATH)"

deb:
	$(CARGO) build --release
	$(CARGO) deb --no-build

clean:
	$(CARGO) clean
