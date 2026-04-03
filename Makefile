# Makefile for the Echo-Location DNS scanner + Orchestrator Bot
#
# Targets:
#   make build-linux-amd64    — standard Linux x86-64 (scattergun + echocatcher)
#   make build-android-arm64  — Termux on Android (scattergun only)
#   make build-linux-arm64    — Linux on ARM64 (scattergun + echocatcher)
#   make build-darwin-arm64   — macOS Apple Silicon (scattergun + echocatcher)
#   make build-bot            — orchestrator bot for Linux amd64 (VPS)
#   make build-all            — all of the above
#   make tidy                 — run go mod tidy
#   make vet                  — run go vet on all packages
#   make clean                — remove the bin/ directory

# -trimpath    strips local filesystem paths from the binary (safer for distribution)
# -s -w        strips symbol table and DWARF debug info (smaller binary)
GOFLAGS := -trimpath -ldflags="-s -w"

SCATTERGUN_PKG  := ./scattergun/
ECHOCATCHER_PKG := ./echocatcher/
BOT_PKG         := ./bot/
BIN := bin

.PHONY: build-linux-amd64 build-android-arm64 build-linux-arm64 build-darwin-arm64 \
        build-bot build-all tidy vet clean

# ---- Individual targets -------------------------------------------------------

build-linux-amd64: $(BIN)
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(BIN)/scattergun-linux-amd64  $(SCATTERGUN_PKG)
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(BIN)/echocatcher-linux-amd64 $(ECHOCATCHER_PKG)
	@echo "Built: $(BIN)/scattergun-linux-amd64  $(BIN)/echocatcher-linux-amd64"

# echocatcher is NOT built for Android: binding port 53 on Android requires root
# or a custom VPN service, which is outside the scope of this tooling.
build-android-arm64: $(BIN)
	GOOS=android GOARCH=arm64 go build $(GOFLAGS) -o $(BIN)/scattergun-android-arm64 $(SCATTERGUN_PKG)
	@echo "Built: $(BIN)/scattergun-android-arm64"

build-linux-arm64: $(BIN)
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o $(BIN)/scattergun-linux-arm64  $(SCATTERGUN_PKG)
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o $(BIN)/echocatcher-linux-arm64 $(ECHOCATCHER_PKG)
	@echo "Built: $(BIN)/scattergun-linux-arm64  $(BIN)/echocatcher-linux-arm64"

build-darwin-arm64: $(BIN)
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -o $(BIN)/scattergun-darwin-arm64  $(SCATTERGUN_PKG)
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -o $(BIN)/echocatcher-darwin-arm64 $(ECHOCATCHER_PKG)
	@echo "Built: $(BIN)/scattergun-darwin-arm64  $(BIN)/echocatcher-darwin-arm64"

# The orchestrator bot runs on the VPS (linux/amd64 only).
# It is NOT cross-compiled for Android — it binds no ports but needs
# systemctl which is Linux-specific.
build-bot: $(BIN)
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(BIN)/orchestrator-bot-linux-amd64 $(BOT_PKG)
	@echo "Built: $(BIN)/orchestrator-bot-linux-amd64"

# ---- Aggregate targets --------------------------------------------------------

build-all: build-linux-amd64 build-android-arm64 build-linux-arm64 build-darwin-arm64 build-bot
	@echo "All targets built successfully."

# ---- Utility targets ----------------------------------------------------------

$(BIN):
	mkdir -p $(BIN)

tidy:
	go mod tidy

vet:
	go vet ./...

clean:
	rm -rf $(BIN)/
