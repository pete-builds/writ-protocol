#!/bin/bash
# Run the writ-hook gate as its own macOS user, so the user Claude Code's tools
# run as cannot read the gate's keys, grants, store, or audit record.
#
#   sudo bash writ-gate-macos.sh install BINARY [SHA256]
#   sudo bash writ-gate-macos.sh retire OLD_WRIT_HOME
#   sudo bash writ-gate-macos.sh unretire OLD_WRIT_HOME
#   sudo bash writ-gate-macos.sh uninstall
#
# install creates a hidden account (_writ, no shell, no password), copies
# BINARY to a root-owned path (refusing it unless its SHA-256 matches, when
# given), makes fresh keys and a rolling grant as _writ, and starts two
# LaunchDaemons as _writ: the gate on a Unix socket, and a renewal that keeps
# the grant fresh. Point the hooks at the socket afterwards (docs/claude-code.md).
#
# retire moves the three seed files of a gate that ran in place, as your user,
# into a root-only directory, so they can no longer sign; its receipts still
# verify, since `writ-hook receipts` needs only root.did. Run it after the
# hooks point at the socket. unretire puts them back.
#
# uninstall stops both daemons and removes the account and the binary. It
# leaves the state directory, which holds the keys and receipts, in place.
set -eu

GATE_USER=_writ
GATE_ID=350
BIN=/usr/local/bin/writ-hook
STATE=/var/db/writ
GATE_HOME=$STATE/home
RUN_DIR=$STATE/run
SOCKET=$RUN_DIR/gate.sock
LOG_DIR=$STATE/log
RETIRED=$STATE/retired
GATE_LABEL=org.writ.gate
RENEW_LABEL=org.writ.renew
GRANT_ARGS="grant -name session -uses 10000 -ttl 24h -renew-before 22h"

die() { echo "writ-gate-macos: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run it with sudo"
[ "$(uname -s)" = Darwin ] || die "macOS only; on Linux see docs/claude-code.md"

as_gate() {
	sudo -u "$GATE_USER" env -i HOME="$STATE" WRIT_HOME="$GATE_HOME" "$BIN" "$@"
}

# plist LABEL INTERVAL ARG...: a LaunchDaemon run as the gate user. INTERVAL 0
# keeps it alive; otherwise it runs every INTERVAL seconds.
plist() {
	label=$1 interval=$2
	shift 2
	echo '<?xml version="1.0" encoding="UTF-8"?>'
	echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
	echo '<plist version="1.0"><dict>'
	echo "  <key>Label</key><string>$label</string>"
	echo "  <key>UserName</key><string>$GATE_USER</string>"
	echo "  <key>GroupName</key><string>$GATE_USER</string>"
	echo '  <key>ProgramArguments</key><array>'
	echo "    <string>$BIN</string>"
	for a in "$@"; do echo "    <string>$a</string>"; done
	echo '  </array>'
	echo '  <key>EnvironmentVariables</key><dict>'
	echo "    <key>WRIT_HOME</key><string>$GATE_HOME</string>"
	echo "    <key>HOME</key><string>$STATE</string>"
	echo '  </dict>'
	echo '  <key>Umask</key><integer>63</integer>'
	echo '  <key>RunAtLoad</key><true/>'
	if [ "$interval" -eq 0 ]; then
		echo '  <key>KeepAlive</key><true/>'
	else
		echo "  <key>StartInterval</key><integer>$interval</integer>"
	fi
	echo "  <key>StandardOutPath</key><string>$LOG_DIR/$label.log</string>"
	echo "  <key>StandardErrorPath</key><string>$LOG_DIR/$label.log</string>"
	echo '</dict></plist>'
}

start() {
	path=/Library/LaunchDaemons/$1.plist
	launchctl bootout "system/$1" 2>/dev/null || true
	launchctl enable "system/$1"
	launchctl bootstrap system "$path"
}

install_gate() {
	src=$1 want=${2:-}
	[ -f "$src" ] || die "no binary at $src"
	if [ -n "$want" ]; then
		got=$(shasum -a 256 "$src" | cut -d' ' -f1)
		[ "$got" = "$want" ] || die "$src has SHA-256 $got, not $want"
	fi

	if ! dscl . -read "/Users/$GATE_USER" >/dev/null 2>&1; then
		[ -z "$(dscl . -search /Users UniqueID "$GATE_ID")" ] || die "uid $GATE_ID is taken"
		[ -z "$(dscl . -search /Groups PrimaryGroupID "$GATE_ID")" ] || die "gid $GATE_ID is taken"
		dscl . -create "/Groups/$GATE_USER"
		dscl . -create "/Groups/$GATE_USER" PrimaryGroupID "$GATE_ID"
		dscl . -create "/Groups/$GATE_USER" RealName "Writ gate"
		dscl . -create "/Groups/$GATE_USER" Password '*'
		dscl . -create "/Users/$GATE_USER"
		dscl . -create "/Users/$GATE_USER" UniqueID "$GATE_ID"
		dscl . -create "/Users/$GATE_USER" PrimaryGroupID "$GATE_ID"
		dscl . -create "/Users/$GATE_USER" UserShell /usr/bin/false
		dscl . -create "/Users/$GATE_USER" NFSHomeDirectory "$STATE"
		dscl . -create "/Users/$GATE_USER" RealName "Writ gate"
		dscl . -create "/Users/$GATE_USER" Password '*'
		dscl . -create "/Users/$GATE_USER" IsHidden 1
		echo "created $GATE_USER ($GATE_ID)"
	fi

	install -o root -g wheel -m 0755 "$src" "$BIN"
	install -d -o root -g wheel -m 0755 "$STATE"
	install -d -o "$GATE_USER" -g "$GATE_USER" -m 0700 "$GATE_HOME"
	install -d -o "$GATE_USER" -g "$GATE_USER" -m 0755 "$RUN_DIR"
	install -d -o "$GATE_USER" -g "$GATE_USER" -m 0750 "$LOG_DIR"

	as_gate init
	# shellcheck disable=SC2086 # GRANT_ARGS is a word list on purpose
	as_gate $GRANT_ARGS

	# shellcheck disable=SC2086
	plist "$RENEW_LABEL" 900 $GRANT_ARGS >"/Library/LaunchDaemons/$RENEW_LABEL.plist"
	plist "$GATE_LABEL" 0 serve -socket "$SOCKET" >"/Library/LaunchDaemons/$GATE_LABEL.plist"
	for l in "$GATE_LABEL" "$RENEW_LABEL"; do
		chown root:wheel "/Library/LaunchDaemons/$l.plist"
		chmod 0644 "/Library/LaunchDaemons/$l.plist"
		plutil -lint "/Library/LaunchDaemons/$l.plist" >/dev/null
		start "$l"
	done

	i=0
	while [ ! -S "$SOCKET" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
	[ -S "$SOCKET" ] || die "the gate did not open $SOCKET; see $LOG_DIR/$GATE_LABEL.log"
	ls -ld "$STATE" "$GATE_HOME" "$RUN_DIR" "$SOCKET" "$BIN"
	echo "gate listening on $SOCKET as $GATE_USER; set WRIT_HOOK_SOCKET=$SOCKET in the hooks"
}

seeds() { echo "$1/root.seed $1/claude/agent.seed $1/claude/gate.seed"; }

retire() {
	old=${1%/}
	[ -n "$old" ] && [ -f "$old/root.did" ] || die "$old is not a WRIT_HOME (no root.did)"
	install -d -o root -g wheel -m 0700 "$RETIRED"
	for f in $(seeds "$old"); do
		[ -f "$f" ] || die "no $f"
	done
	for f in $(seeds "$old"); do
		mv "$f" "$RETIRED/$(basename "$f")"
	done
	echo "$old" >"$RETIRED/ORIGIN"
	echo "moved the seeds of $old to $RETIRED (root only); its receipts still verify"
}

unretire() {
	old=${1%/}
	owner=$(stat -f %Su "$old/root.did") || die "$old is not a WRIT_HOME"
	for f in $(seeds "$old"); do
		mv "$RETIRED/$(basename "$f")" "$f"
		chown "$owner" "$f"
		chmod 0600 "$f"
	done
	rm -f "$RETIRED/ORIGIN"
	echo "restored the seeds of $old"
}

uninstall_gate() {
	for l in "$GATE_LABEL" "$RENEW_LABEL"; do
		launchctl bootout "system/$l" 2>/dev/null || true
		rm -f "/Library/LaunchDaemons/$l.plist"
	done
	rm -f "$BIN"
	dscl . -delete "/Users/$GATE_USER" 2>/dev/null || true
	dscl . -delete "/Groups/$GATE_USER" 2>/dev/null || true
	echo "removed the daemons, $BIN, and $GATE_USER; $STATE is left in place"
}

case "${1:-}" in
install) [ $# -ge 2 ] || die "install BINARY [SHA256]"; install_gate "$2" "${3:-}" ;;
retire) [ $# -eq 2 ] || die "retire OLD_WRIT_HOME"; retire "$2" ;;
unretire) [ $# -eq 2 ] || die "unretire OLD_WRIT_HOME"; unretire "$2" ;;
uninstall) uninstall_gate ;;
*) die "usage: install BINARY [SHA256] | retire OLD_WRIT_HOME | unretire OLD_WRIT_HOME | uninstall" ;;
esac
