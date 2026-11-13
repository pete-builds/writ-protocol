#!/bin/bash
# Run the writ-hook gate as its own macOS user, so the user Claude Code's tools
# run as cannot read the gate's keys, grants, store, or audit record.
#
#   sudo /bin/bash writ-gate-macos.sh install BINARY SHA256
#   sudo /bin/bash writ-gate-macos.sh install --no-checksum BINARY
#   sudo /bin/bash writ-gate-macos.sh uninstall
#
# Run it from a fresh clone at a commit you reviewed, never from a working tree
# the agent can write, and take SHA256 from somewhere the agent cannot write
# either: a release page, or a build in that clean clone (docs/claude-code.md
# has the checklist).
#
# install creates a hidden account (_writ, no shell, no password), copies
# BINARY into a root-owned folder (refusing it unless its SHA-256 matches),
# makes keys and a rolling grant as _writ, and starts two LaunchDaemons as
# _writ: the gate on a Unix socket, and a renewal that keeps the grant fresh.
# Point the hooks at the socket afterwards (docs/claude-code.md). It refuses a
# program folder that any directory above makes writable by someone other than
# root, and if any step fails or is interrupted it undoes what that run
# created, so a first install either completes or leaves nothing behind.
#
# uninstall stops both daemons, kills anything left running as the gate, and
# removes the account and the binary. It leaves the state directory, which
# holds the keys and receipts, in place, owned by root, so no account later
# given the gate's uid can read it.
#
# Two settings, for testing and narrowing, read from the environment:
#   WRIT_GATE_LIBEXEC  the program folder (default /usr/local/libexec/writ);
#                      uninstall needs the same value
#   WRIT_GATE_GRANT    the standing grant the install signs and the renewal
#                      keeps (default "grant -name session -uses 10000 -ttl
#                      24h -renew-before 22h": any tool, any path); it must
#                      keep -name session and set -uses above 0
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 022

GATE_USER=_writ
GATE_ID=350
LIBEXEC=${WRIT_GATE_LIBEXEC:-/usr/local/libexec/writ}
BIN=$LIBEXEC/writ-hook
STATE=/var/db/writ
GATE_HOME=$STATE/home
RUN_DIR=$STATE/run
SOCKET=$RUN_DIR/gate.sock
LOG_DIR=$STATE/log
GATE_LABEL=org.writ.gate
RENEW_LABEL=org.writ.renew
GRANT_ARGS=${WRIT_GATE_GRANT:-grant -name session -uses 10000 -ttl 24h -renew-before 22h}

die() { echo "writ-gate-macos: $*" >&2; exit 1; }

check_settings() {
	case $LIBEXEC in /*) ;; *) die "WRIT_GATE_LIBEXEC must be an absolute path" ;; esac
	case $LIBEXEC in *[!A-Za-z0-9/._-]*) die "WRIT_GATE_LIBEXEC holds a character other than letters, digits, and / . _ -" ;; esac
	case $LIBEXEC in */./* | */../* | */. | */..) die "WRIT_GATE_LIBEXEC must not hold . or .. segments" ;; esac
	case $LIBEXEC in
	/var/db/writ | /var/db/writ/* | /private/var/db/writ | /private/var/db/writ/*)
		die "WRIT_GATE_LIBEXEC must not be inside the gate's state, $STATE" ;;
	esac
	case $GRANT_ARGS in *[!A-Za-z0-9\ ,._/-]*) die "WRIT_GATE_GRANT holds a character other than letters, digits, space, and , . _ / -" ;; esac
	# shellcheck disable=SC2086 # split the word list; it holds no glob characters
	set -- $GRANT_ARGS
	[ "${1:-}" = grant ] || die "WRIT_GATE_GRANT must start with \"grant\""
	shift
	name='' uses=''
	while [ $# -gt 0 ]; do
		case $1 in
		-name | --name) name=${2:-} ;;
		-name=* | --name=*) name=${1#*=} ;;
		-uses | --uses) uses=${2:-} ;;
		-uses=* | --uses=*) uses=${1#*=} ;;
		esac
		shift
	done
	# Another name would leave the old any-tool session grant in force until
	# it expires, up to 24 hours.
	[ "$name" = session ] || die "WRIT_GATE_GRANT must keep -name session"
	case $uses in '' | *[!0-9]*) die "WRIT_GATE_GRANT must set -uses to a number above 0; without it, or with 0, the grant has no limit" ;; esac
	[ "$uses" -gt 0 ] || die "WRIT_GATE_GRANT must set -uses to a number above 0; 0 means no limit"
}

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
	launchctl bootout "system/$1" 2>/dev/null || true
	launchctl enable "system/$1"
	launchctl bootstrap system "/Library/LaunchDaemons/$1.plist"
}

# safe_dir DIR: refuse DIR unless it is a real directory owned by root that
# neither its group nor others can write, since whoever can write a folder can
# rename what is in it and put their own program in its place.
safe_dir() {
	[ ! -L "$1" ] || die "$1 is a symbolic link; the program folder and every folder above it must be real directories"
	info=$(stat -f '%Su %Lp' "$1") || die "cannot stat $1"
	owner=${info% *} mode=${info#* }
	[ "$owner" = root ] || die "$1 is owned by $owner, not root, so that user could replace the gate's program; choose WRIT_GATE_LIBEXEC under root-owned folders"
	[ $((8#$mode & 8#022)) -eq 0 ] || die "$1 has mode $mode, writable by its group or by everyone, so they could replace the gate's program"
}

# user_attr NAME, group_attr NAME: one attribute of the gate account or its
# group, as dscl prints it. dscl prints an attribute it has no standard name
# for, such as IsHidden, with a dsAttrTypeNative: prefix.
user_attr() {
	dscl . -read "/Users/$GATE_USER" "$1" 2>/dev/null | sed -n -e "s/^$1: //p" -e "s/^dsAttrTypeNative:$1: //p"
}
group_attr() {
	dscl . -read "/Groups/$GATE_USER" "$1" 2>/dev/null | sed -n -e "s/^$1: //p" -e "s/^dsAttrTypeNative:$1: //p"
}

# unsafe_entries DIR...: every entry that is not a directory, a socket, or a
# regular file with one name. A root chown follows a hard link to its inode,
# so a name the gate linked to a root file would hand that file over.
unsafe_entries() {
	find "$@" -xdev ! -type d ! -type s ! \( -type f -links 1 \) -print
}

# own_state USER:GROUP DIR...: chown every directory, socket, and regular file
# under DIR, never through a link. Run it only when nothing runs as the gate
# and unsafe_entries is empty, so no name can change underneath it.
own_state() {
	who=$1
	shift
	find "$@" -xdev -depth \( -type d -o -type s -o -type f \) -exec chown -h "$who" {} +
}

# state_to_root: stop anything running as the gate, remove every name that
# is not a directory, a socket, or a single-named regular file (removing a
# name never touches the inode it points to), then make the rest root's.
state_to_root() {
	pkill -9 -U "$GATE_ID" 2>/dev/null || true
	[ -d "$STATE" ] || return 0
	find "$STATE" -xdev ! -type d ! -type s ! \( -type f -links 1 \) -exec rm -f {} +
	own_state root:wheel "$STATE"
}

install_gate() {
	src=$1 want=$2
	[ -f "$src" ] || die "no binary at $src"
	if [ -n "$want" ]; then
		case $want in *[!0-9a-f]*) die "SHA256 must be 64 lowercase hex digits" ;; esac
		[ ${#want} -eq 64 ] || die "SHA256 must be 64 lowercase hex digits"
	fi

	# Every check that can refuse runs before anything is created.
	have_user=''
	if dscl . -read "/Users/$GATE_USER" >/dev/null 2>&1; then
		[ "$(user_attr UniqueID)" = "$GATE_ID" ] || die "$GATE_USER exists with uid $(user_attr UniqueID), not $GATE_ID"
		[ "$(user_attr PrimaryGroupID)" = "$GATE_ID" ] || die "$GATE_USER exists with primary group $(user_attr PrimaryGroupID), not $GATE_ID"
		[ "$(user_attr UserShell)" = /usr/bin/false ] || die "$GATE_USER exists with shell $(user_attr UserShell), not /usr/bin/false"
		[ "$(user_attr IsHidden)" = 1 ] || die "$GATE_USER exists and is not hidden"
		[ "$(user_attr Password)" = '*' ] || die "$GATE_USER exists with password field \"$(user_attr Password)\", not \"*\""
		[ "$(group_attr PrimaryGroupID)" = "$GATE_ID" ] || die "group $GATE_USER has gid $(group_attr PrimaryGroupID), not $GATE_ID"
		[ -z "$(group_attr GroupMembership)" ] || die "group $GATE_USER has members: $(group_attr GroupMembership)"
		have_user=1
	else
		! dscl . -read "/Groups/$GATE_USER" >/dev/null 2>&1 || die "a group $GATE_USER exists with no account $GATE_USER; remove it or find out who made it"
		uids=$(dscl . -search /Users UniqueID "$GATE_ID") || die "could not search the accounts for uid $GATE_ID"
		[ -z "$uids" ] || die "uid $GATE_ID is taken"
		gids=$(dscl . -search /Groups PrimaryGroupID "$GATE_ID") || die "could not search the groups for gid $GATE_ID"
		[ -z "$gids" ] || die "gid $GATE_ID is taken"
		! pgrep -U "$GATE_ID" >/dev/null || die "processes run as uid $GATE_ID with no account $GATE_USER"
	fi
	missing=''
	d=$LIBEXEC
	while [ ! -e "$d" ] && [ ! -L "$d" ]; do
		missing="$d $missing"
		d=$(dirname "$d")
	done
	while :; do
		safe_dir "$d"
		[ "$d" != / ] || break
		d=$(dirname "$d")
	done

	# From here on a failure or an interruption undoes what this run created
	# (rollback). A failed reinstall keeps the account and state it found, but
	# not the binary and plists it replaced.
	made_dirs='' made_tmp='' made_bin='' made_state='' made_user='' made_daemons=''
	trap rollback EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM HUP

	for d in $missing; do
		made_dirs="$d $made_dirs"
		install -d -o root -g wheel -m 0755 "$d"
	done
	safe_dir "$LIBEXEC"

	# Hash the copy root now holds, not the source, which its owner could
	# change between the check and the copy.
	made_tmp=$(mktemp "$LIBEXEC/.writ-hook.XXXXXX")
	cat "$src" >"$made_tmp"
	if [ -n "$want" ]; then
		got=$(shasum -a 256 "$made_tmp" | cut -d' ' -f1)
		[ "$got" = "$want" ] || die "$src has SHA-256 $got, not $want"
	fi
	chown root:wheel "$made_tmp"
	chmod 0755 "$made_tmp"
	[ -e "$BIN" ] || made_bin=1
	mv -f "$made_tmp" "$BIN"
	made_tmp=''
	[ -e "$STATE" ] || made_state=1

	if [ -z "$have_user" ]; then
		made_user=1
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

	install -d -o root -g wheel -m 0755 "$STATE"
	install -d -o "$GATE_USER" -g "$GATE_USER" -m 0700 "$GATE_HOME"
	install -d -o "$GATE_USER" -g "$GATE_USER" -m 0755 "$RUN_DIR"
	# The log folder is root's: launchd, as root, opens the log files, so a
	# link the gate could plant there would aim root at a file of its choice.
	install -d -o root -g wheel -m 0755 "$LOG_DIR"
	chown -h root:wheel "$LOG_DIR"
	chmod 0755 "$LOG_DIR"
	for l in "$GATE_LABEL" "$RENEW_LABEL"; do
		rm -f "$LOG_DIR/$l.log"
		: >"$LOG_DIR/$l.log"
		chown "$GATE_USER:$GATE_USER" "$LOG_DIR/$l.log"
		chmod 0640 "$LOG_DIR/$l.log"
	done

	# State kept by an uninstall is root's. Hand it back only to an account
	# this run made, so nothing runs as the gate yet, and only when every name
	# in it is a folder, a socket, or a single-named file.
	if [ -n "$made_user" ]; then
		! pgrep -U "$GATE_ID" >/dev/null || die "processes run as uid $GATE_ID before the gate started"
		bad=$(unsafe_entries "$GATE_HOME" "$RUN_DIR" "$LOG_DIR")
		[ -z "$bad" ] || die "the state holds links or special files, which a root chown could follow: $bad"
		own_state "$GATE_USER:$GATE_USER" "$GATE_HOME" "$RUN_DIR"
	fi

	as_gate init
	echo "standing grant: $GRANT_ARGS"
	# shellcheck disable=SC2086 # GRANT_ARGS is a word list on purpose
	as_gate $GRANT_ARGS

	[ -e "/Library/LaunchDaemons/$GATE_LABEL.plist" ] || [ -e "/Library/LaunchDaemons/$RENEW_LABEL.plist" ] || made_daemons=1
	# shellcheck disable=SC2086
	plist "$RENEW_LABEL" 900 $GRANT_ARGS >"/Library/LaunchDaemons/$RENEW_LABEL.plist"
	plist "$GATE_LABEL" 0 serve -socket "$SOCKET" >"/Library/LaunchDaemons/$GATE_LABEL.plist"
	# A gate stopped by a reinstall leaves its socket file; remove it, so the
	# wait below sees the new gate's socket and not the old one.
	rm -f "$SOCKET"
	for l in "$GATE_LABEL" "$RENEW_LABEL"; do
		chown root:wheel "/Library/LaunchDaemons/$l.plist"
		chmod 0644 "/Library/LaunchDaemons/$l.plist"
		plutil -lint "/Library/LaunchDaemons/$l.plist" >/dev/null
		start "$l"
	done

	i=0
	while [ ! -S "$SOCKET" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
	[ -S "$SOCKET" ] || die "the gate did not open $SOCKET; see $LOG_DIR/$GATE_LABEL.log"
	trap - EXIT INT TERM HUP
	ls -ld "$STATE" "$GATE_HOME" "$RUN_DIR" "$SOCKET" "$LOG_DIR" "$LIBEXEC" "$BIN"
	echo "gate listening on $SOCKET as $GATE_USER; set WRIT_HOOK_SOCKET=$SOCKET in the hooks"
}

# shellcheck disable=SC2329 # run by the EXIT trap in install_gate
# rollback runs when install exits early. It removes only what this run
# created, so a failed reinstall keeps the account, keys, and receipts that
# were there before it.
rollback() {
	rc=$?
	[ "$rc" -ne 0 ] || return 0
	trap - INT TERM HUP
	echo "writ-gate-macos: install failed; undoing what this run created" >&2
	if [ -n "$made_daemons" ]; then
		for l in "$GATE_LABEL" "$RENEW_LABEL"; do
			launchctl bootout "system/$l" 2>/dev/null || true
			rm -f "/Library/LaunchDaemons/$l.plist"
		done
	fi
	if [ -n "$made_user" ]; then
		# State kept from before goes back to root, as uninstall left it,
		# rather than stay owned by a uid with no account.
		if [ -z "$made_state" ]; then state_to_root; else pkill -9 -U "$GATE_ID" 2>/dev/null || true; fi
		dscl . -delete "/Users/$GATE_USER" 2>/dev/null || true
		dscl . -delete "/Groups/$GATE_USER" 2>/dev/null || true
	fi
	[ -z "$made_state" ] || rm -rf "$STATE"
	[ -z "$made_tmp" ] || rm -f "$made_tmp"
	[ -z "$made_bin" ] || rm -f "$BIN"
	for d in $made_dirs; do
		rmdir "$d" 2>/dev/null || true
	done
	echo "writ-gate-macos: undone" >&2
	exit "$rc"
}

uninstall_gate() {
	for l in "$GATE_LABEL" "$RENEW_LABEL"; do
		launchctl bootout "system/$l" 2>/dev/null || true
		rm -f "/Library/LaunchDaemons/$l.plist"
	done
	# The kept keys and receipts become root's, so an account later given
	# uid $GATE_ID cannot read them.
	state_to_root
	rm -f "$BIN"
	rmdir "$LIBEXEC" 2>/dev/null || true
	dscl . -delete "/Users/$GATE_USER" 2>/dev/null || true
	dscl . -delete "/Groups/$GATE_USER" 2>/dev/null || true
	echo "removed the daemons, $BIN, and $GATE_USER; $STATE is left in place, owned by root"
}

main() {
	[ "$(id -u)" -eq 0 ] || die "run it with sudo"
	[ "$(uname -s)" = Darwin ] || die "macOS only; on Linux see docs/claude-code.md"
	check_settings
	echo "program folder: $LIBEXEC"
	case "${1:-}" in
	install)
		if [ "${2:-}" = --no-checksum ]; then
			[ $# -eq 3 ] || die "install --no-checksum BINARY"
			install_gate "$3" ""
		else
			[ $# -eq 3 ] || die "install BINARY SHA256 (or install --no-checksum BINARY)"
			install_gate "$2" "$3"
		fi
		;;
	uninstall) uninstall_gate ;;
	*) die "usage: install BINARY SHA256 | install --no-checksum BINARY | uninstall" ;;
	esac
}

# Bash reads a script as it runs it, so lines appended to this file while it
# runs would run too; with everything in main and this the last line, bash
# has read all of it before anything runs, and exits before reading more.
main "$@"; exit
