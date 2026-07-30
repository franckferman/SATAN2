# ─────────────────────────────────────────────────────────────────────────────
# SATAN2 — Makefile
# Secure Anti-Forensics and Total Annihilation of iNformation
# ─────────────────────────────────────────────────────────────────────────────

SHELL := bash
.SHELLFLAGS := -e -c
.ONESHELL:
.DEFAULT_GOAL := help

# ── Colours ──────────────────────────────────────────────────────────────────
RED    := \033[0;31m
BOLD   := \033[1m
RESET  := \033[0m
DIM    := \033[2m

# ── Paths ─────────────────────────────────────────────────────────────────────
TARGET_DIR   := target
DIST_DIR     := dist
LINUX_BIN    := $(TARGET_DIR)/release/satan2
MUSL_BIN     := $(TARGET_DIR)/x86_64-unknown-linux-musl/release/satan2
ARM64_BIN    := $(TARGET_DIR)/aarch64-unknown-linux-gnu/release/satan2
WIN_BIN      := $(TARGET_DIR)/x86_64-pc-windows-gnu/release/satan2_win.exe
INSTALL_DIR  := /usr/local/bin

# ── Targets ──────────────────────────────────────────────────────────────────
LINUX_TARGET := x86_64-unknown-linux-gnu
MUSL_TARGET  := x86_64-unknown-linux-musl
ARM64_TARGET := aarch64-unknown-linux-gnu
WIN_TARGET   := x86_64-pc-windows-gnu

# ── Flags ─────────────────────────────────────────────────────────────────────
RELEASE_FLAGS   := -C opt-level=3 -C codegen-units=1 -C strip=symbols
STEALTH_FLAGS   := -C opt-level=3 -C codegen-units=1 -C strip=symbols \
                   -C panic=abort -C lto=fat -C embed-bitcode=no
HARDENED_FLAGS  := -C opt-level=2 -C strip=debuginfo \
                   -C relro-level=full -C control-flow-protection=full
DEBUG_FLAGS     := -C opt-level=0 -C debuginfo=2

# ── Version ───────────────────────────────────────────────────────────────────
VERSION := $(shell cargo metadata --no-deps --format-version 1 \
             | python3 -c "import sys,json; \
               pkgs=[p for p in json.load(sys.stdin)['packages'] if p['name']=='satan2-cli']; \
               print(pkgs[0]['version'] if pkgs else 'unknown')" 2>/dev/null || echo "dev")

# ── Cross-target guard ────────────────────────────────────────────────────────
# ensure_target <rust-target>: install via rustup when available; on machines
# without rustup, verify the target is already installed (e.g. via a distro
# package) and fail with an actionable message instead of a raw rustc error.
define ensure_target
	@if command -v rustup &>/dev/null; then \
		rustup target add $(1); \
	elif ! [ -d "$$(rustc --print target-libdir --target $(1) 2>/dev/null)" ]; then \
		echo "error: rust target '$(1)' is not installed and rustup was not found."; \
		echo "       install it with 'rustup target add $(1)' (see rustup.rs) or via"; \
		echo "       your distribution's Rust target package, then re-run make."; \
		exit 1; \
	fi
endef

# ─────────────────────────────────────────────────────────────────────────────
.PHONY: help build release windows arm64 musl all \
        stealth hardened poly poly-n \
        check test fmt clippy audit fix \
        strip dist install uninstall \
        clean distclean tag

# ─────────────────────────────────────────────────────────────────────────────
help:
	@printf "$(BOLD)$(RED)☢  SATAN2 $(VERSION) — Build System$(RESET)\n\n"
	@printf "$(BOLD)Standard Builds$(RESET)\n"
	@printf "  $(BOLD)make build$(RESET)        Dev build (unoptimised, with symbols)\n"
	@printf "  $(BOLD)make release$(RESET)      Release build — Linux x86-64 (glibc)\n"
	@printf "  $(BOLD)make musl$(RESET)         Static release — Linux x86-64 (musl, no libc dep)\n"
	@printf "  $(BOLD)make arm64$(RESET)        Release build — Linux ARM64 (cross)\n"
	@printf "  $(BOLD)make windows$(RESET)      Release build — Windows x86-64 (cross, MinGW)\n"
	@printf "  $(BOLD)make all$(RESET)          Build all targets (linux + musl + arm64 + windows)\n"
	@printf "\n$(BOLD)Hardened / Stealth Variants$(RESET)\n"
	@printf "  $(BOLD)make stealth$(RESET)      LTO + panic=abort + max strip — minimal footprint\n"
	@printf "  $(BOLD)make hardened$(RESET)     RELRO + CFP + debuginfo strip — hardened binary\n"
	@printf "\n$(BOLD)Polymorphic Builds$(RESET)\n"
	@printf "  $(BOLD)make poly$(RESET)         3 polymorphic variants (unique hash, same behaviour)\n"
	@printf "  $(BOLD)make poly-n N=5$(RESET)   N polymorphic variants\n"
	@printf "\n$(BOLD)Quality$(RESET)\n"
	@printf "  $(BOLD)make check$(RESET)        cargo check --workspace\n"
	@printf "  $(BOLD)make test$(RESET)         cargo test --workspace\n"
	@printf "  $(BOLD)make fmt$(RESET)          cargo fmt --all\n"
	@printf "  $(BOLD)make clippy$(RESET)       cargo clippy --workspace --tests -- -D warnings\n"
	@printf "  $(BOLD)make audit$(RESET)        cargo audit (advisory DB)\n"
	@printf "  $(BOLD)make fix$(RESET)          cargo fix + fmt\n"
	@printf "\n$(BOLD)Packaging$(RESET)\n"
	@printf "  $(BOLD)make strip$(RESET)        Strip release binaries in-place\n"
	@printf "  $(BOLD)make dist$(RESET)         Create distribution archives in dist/\n"
	@printf "  $(BOLD)make install$(RESET)      Install linux binary → $(INSTALL_DIR)/satan2\n"
	@printf "  $(BOLD)make uninstall$(RESET)    Remove installed binary\n"
	@printf "\n$(BOLD)Release$(RESET)\n"
	@printf "  $(BOLD)make tag V=1.2.0$(RESET)  Create and push git tag v1.2.0 → triggers CI release\n"
	@printf "\n$(BOLD)Cleanup$(RESET)\n"
	@printf "  $(BOLD)make clean$(RESET)        cargo clean\n"
	@printf "  $(BOLD)make distclean$(RESET)    cargo clean + remove dist/\n"

# ─────────────────────────────────────────────────────────────────────────────
# Standard Builds
# ─────────────────────────────────────────────────────────────────────────────

build:
	@printf "$(DIM)→ dev build$(RESET)\n"
	RUSTFLAGS="$(DEBUG_FLAGS)" cargo build -p satan2-cli

release:
	@printf "$(DIM)→ release linux x86-64$(RESET)\n"
	RUSTFLAGS="$(RELEASE_FLAGS)" cargo build --release -p satan2-cli
	@printf "$(RED)✓$(RESET) $(LINUX_BIN)\n"

musl:
	@printf "$(DIM)→ static musl x86-64$(RESET)\n"
	$(call ensure_target,$(MUSL_TARGET))
	RUSTFLAGS="$(RELEASE_FLAGS)" cargo build --release \
		-p satan2-cli --target $(MUSL_TARGET)
	@printf "$(RED)✓$(RESET) $(MUSL_BIN)\n"

arm64:
	@printf "$(DIM)→ cross linux arm64$(RESET)\n"
	$(call ensure_target,$(ARM64_TARGET))
	@command -v aarch64-linux-gnu-gcc &>/dev/null || \
		{ echo "Install: sudo apt install gcc-aarch64-linux-gnu"; exit 1; }
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
	RUSTFLAGS="$(RELEASE_FLAGS)" \
		cargo build --release -p satan2-cli --target $(ARM64_TARGET)
	@printf "$(RED)✓$(RESET) $(ARM64_BIN)\n"

windows:
	@printf "$(DIM)→ cross windows x86-64$(RESET)\n"
	$(call ensure_target,$(WIN_TARGET))
	@command -v x86_64-w64-mingw32-gcc &>/dev/null || \
		{ echo "Install: sudo apt install gcc-mingw-w64-x86-64"; exit 1; }
	RUSTFLAGS="$(RELEASE_FLAGS)" cargo build --release \
		-p satan2-win --target $(WIN_TARGET)
	@printf "$(RED)✓$(RESET) $(WIN_BIN)\n"

all: release musl arm64 windows
	@printf "$(RED)$(BOLD)✓ All targets built$(RESET)\n"

# ─────────────────────────────────────────────────────────────────────────────
# Hardened / Stealth
# ─────────────────────────────────────────────────────────────────────────────

stealth:
	@printf "$(DIM)→ stealth build (LTO + panic=abort + full strip)$(RESET)\n"
	RUSTFLAGS="$(STEALTH_FLAGS)" cargo build --release -p satan2-cli
	@strip -s $(LINUX_BIN) 2>/dev/null || true
	@# Optional UPX compression if available
	@if command -v upx &>/dev/null; then \
		upx --best --lzma $(LINUX_BIN) && printf "$(RED)✓$(RESET) UPX compressed\n"; \
	fi
	@printf "$(RED)✓$(RESET) stealth: $$(du -sh $(LINUX_BIN) | cut -f1)\n"

hardened:
	@printf "$(DIM)→ hardened build (RELRO + CFP)$(RESET)\n"
	RUSTFLAGS="$(HARDENED_FLAGS)" cargo build --release -p satan2-cli
	@printf "$(RED)✓$(RESET) $(LINUX_BIN)\n"

# ─────────────────────────────────────────────────────────────────────────────
# Polymorphic Builds
#
# Produces N binaries with identical behaviour but different hashes.
# Each build injects a unique 64-bit nonce compiled into the binary via
# the SATAN2_BUILD_NONCE env var (read by build.rs at compile time),
# forcing rustc to recompile and produce a distinct output binary.
# Use case: distribute different copies per operator / target to prevent
# cross-correlation of binaries via hash comparison.
# ─────────────────────────────────────────────────────────────────────────────

N ?= 3

poly:
	@$(MAKE) poly-n N=$(N)

poly-n:
	@printf "$(DIM)→ polymorphic build × $(N) variants$(RESET)\n"
	@mkdir -p $(DIST_DIR)/poly
	@for i in $$(seq 1 $(N)); do \
		NONCE=$$(head -c 8 /dev/urandom | xxd -p); \
		printf "  variant $$i / $(N)  nonce=$$NONCE\n"; \
		SATAN2_BUILD_NONCE=$$NONCE \
		RUSTFLAGS="$(RELEASE_FLAGS)" \
			cargo build --release -p satan2-cli 2>/dev/null; \
		cp $(LINUX_BIN) $(DIST_DIR)/poly/satan2-poly-$$i; \
		H=$$(sha256sum $(DIST_DIR)/poly/satan2-poly-$$i | cut -c1-16); \
		printf "  $(RED)✓$(RESET) variant $$i  sha256=$$H...\n"; \
	done
	@printf "$(RED)$(BOLD)✓ $(N) variants in $(DIST_DIR)/poly/$(RESET)\n"
	@sha256sum $(DIST_DIR)/poly/satan2-poly-* | awk '{print $$1}' | sort -u | wc -l | \
		xargs -I{} printf "  unique hashes: {}/$(N)\n"

# ─────────────────────────────────────────────────────────────────────────────
# Quality
# ─────────────────────────────────────────────────────────────────────────────

check:
	cargo check --workspace

test:
	cargo test --workspace

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --tests -- -D warnings

audit:
	@command -v cargo-audit &>/dev/null || cargo install cargo-audit --quiet
	cargo audit

fix:
	cargo fix --allow-dirty --allow-staged
	cargo fmt --all

# ─────────────────────────────────────────────────────────────────────────────
# Packaging
# ─────────────────────────────────────────────────────────────────────────────

strip:
	@for bin in \
		$(LINUX_BIN) \
		$(MUSL_BIN) \
		$(ARM64_BIN); \
	do \
		[ -f "$$bin" ] && strip -s "$$bin" && printf "$(DIM)stripped $$bin$(RESET)\n" || true; \
	done
	@[ -f "$(WIN_BIN)" ] && \
		x86_64-w64-mingw32-strip "$(WIN_BIN)" 2>/dev/null && \
		printf "$(DIM)stripped $(WIN_BIN)$(RESET)\n" || true

dist: strip
	@mkdir -p $(DIST_DIR)
	@V=$(VERSION)
	# Linux x86-64 glibc
	@if [ -f "$(LINUX_BIN)" ]; then \
		tar -czf $(DIST_DIR)/satan2-$$V-linux-x86_64.tar.gz \
			-C $(TARGET_DIR)/release satan2 \
			-C $(CURDIR) README.md LICENSE; \
		printf "$(RED)✓$(RESET) satan2-$$V-linux-x86_64.tar.gz\n"; \
	fi
	# Linux x86-64 musl
	@if [ -f "$(MUSL_BIN)" ]; then \
		tar -czf $(DIST_DIR)/satan2-$$V-linux-x86_64-musl.tar.gz \
			-C $(TARGET_DIR)/$(MUSL_TARGET)/release satan2 \
			-C $(CURDIR) README.md LICENSE; \
		printf "$(RED)✓$(RESET) satan2-$$V-linux-x86_64-musl.tar.gz\n"; \
	fi
	# Linux ARM64
	@if [ -f "$(ARM64_BIN)" ]; then \
		tar -czf $(DIST_DIR)/satan2-$$V-linux-arm64.tar.gz \
			-C $(TARGET_DIR)/$(ARM64_TARGET)/release satan2 \
			-C $(CURDIR) README.md LICENSE; \
		printf "$(RED)✓$(RESET) satan2-$$V-linux-arm64.tar.gz\n"; \
	fi
	# Windows (zip if available, tar.gz fallback)
	@if [ -f "$(WIN_BIN)" ]; then \
		if command -v zip >/dev/null 2>&1; then \
			(cd $(TARGET_DIR)/$(WIN_TARGET)/release && \
			zip $(CURDIR)/$(DIST_DIR)/satan2-$$V-windows-x86_64.zip \
				satan2_win.exe); \
			printf "$(RED)✓$(RESET) satan2-$$V-windows-x86_64.zip\n"; \
		else \
			tar -czf $(DIST_DIR)/satan2-$$V-windows-x86_64.tar.gz \
				-C $(TARGET_DIR)/$(WIN_TARGET)/release satan2_win.exe \
				-C $(CURDIR) README.md LICENSE; \
			printf "$(DIM)zip not found — satan2-$$V-windows-x86_64.tar.gz instead$(RESET)\n"; \
		fi; \
	fi
	# Checksums
	@(cd $(DIST_DIR) && sha256sum satan2-$$V-* > SHA256SUMS) && \
		printf "$(RED)✓$(RESET) SHA256SUMS\n"
	@printf "$(RED)$(BOLD)✓ dist/$(RESET)\n"
	@ls -lh $(DIST_DIR)/

install: release
	@printf "$(DIM)→ installing to $(INSTALL_DIR)/satan2$(RESET)\n"
	@install -m 755 $(LINUX_BIN) $(INSTALL_DIR)/satan2
	@printf "$(RED)✓$(RESET) installed\n"

uninstall:
	@rm -f $(INSTALL_DIR)/satan2
	@printf "$(DIM)removed $(INSTALL_DIR)/satan2$(RESET)\n"

# ─────────────────────────────────────────────────────────────────────────────
# Release Tag
# ─────────────────────────────────────────────────────────────────────────────

V ?=

tag:
	@[ -n "$(V)" ] || { printf "Usage: make tag V=1.2.0\n"; exit 1; }
	@printf "$(DIM)→ tagging v$(V) and pushing → triggers release CI$(RESET)\n"
	git tag -a "v$(V)" -m "SATAN2 v$(V)"
	git push origin "v$(V)"
	@printf "$(RED)✓$(RESET) v$(V) pushed — watch: gh run list\n"

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────────────────

clean:
	cargo clean

distclean: clean
	rm -rf $(DIST_DIR)
