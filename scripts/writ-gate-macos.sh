#!/bin/bash
# Run the writ-hook gate as its own macOS user, so the user Claude Code's tools
# run as cannot read the gate's keys, grants, store, or audit record.
#
#   sudo /bin/bash writ-gate-macos.sh install BINARY SHA256
#   sudo /bin/bash writ-gate-macos.sh install --no-checksum BINARY
#   sudo /bin/bash writ-gate-macos.sh uninstall [--purge]
#
# Run it from a fresh clone at a commit you reviewed (docs/claude-code.md has
# the checklist). install copies BINARY, if its SHA-256 matches, into a
# root-owned folder, creates the hidden account _writ and a fresh
# /var/db/writ, makes keys and a grant as _writ, and starts the gate and a
# renewal as LaunchDaemons. It never adopts state it did not just create; run
# over a live gate, it leaves the state as it is. A failed or interrupted
# install removes what that run created. uninstall removes the gate's
# crontab, stops everything running as the gate, has the gate archive
# /var/db/writ into a root-only tar file in /var/db (unless --purge) and
# empty it, removes what is left by name, and removes the account and the
# program. Root never changes the owner of, or walks, anything the gate could
# have shaped.
#
# WRIT_GATE_LIBEXEC sets the program folder (default /usr/local/libexec/writ;
# uninstall needs the same value). WRIT_GATE_GRANT sets the standing grant
# (default "grant -name session -uses 10000 -ttl 24h -renew-before 22h": any
# tool, any path) as flag and value pairs from -name -tools -under -uses -ttl
# -renew-before, each at most once, keeping -name session and -uses above 0.
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
LABELS="org.writ.gate org.writ.renew"
GRANT_ARGS=${WRIT_GATE_GRANT:-grant -name session -uses 10000 -ttl 24h -renew-before 22h}

die() { echo "writ-gate-macos: $*" >&2; exit 1; }

check_settings() {
	case $LIBEXEC in /*) ;; *) die "WRIT_GATE_LIBEXEC must be an absolute path" ;; esac
	case $LIBEXEC in *[!A-Za-z0-9/._-]*) die "WRIT_GATE_LIBEXEC holds a character other than letters, digits, and / . _ -" ;; esac
	case $LIBEXEC in *//* | */ | */./* | */../* | */. | */..) die "WRIT_GATE_LIBEXEC must not hold //, a trailing /, or . or .. segments" ;; esac
	# The volume is usually case-insensitive, so compare in lower case.
	case $(echo "$LIBEXEC" | tr '[:upper:]' '[:lower:]') in
	/var/db/writ | /var/db/writ/* | /private/var/db/writ | /private/var/db/writ/*)
		die "WRIT_GATE_LIBEXEC must not be inside the gate's state, $STATE" ;;
	esac
	case $GRANT_ARGS in *[!A-Za-z0-9\ ,._/-]*) die "WRIT_GATE_GRANT holds a character other than letters, digits, space, and , . _ / -" ;; esac
	# Strict flag and value pairs: Go's flag parsing stops at the first word
	# that is not a flag, so anything after a stray word would be ignored.
	# shellcheck disable=SC2086 # split the word list; it holds no glob characters
	set -- $GRANT_ARGS
	[ "${1:-}" = grant ] || die "WRIT_GATE_GRANT must start with \"grant\""
	shift
	name='' uses='' seen=' '
	while [ $# -gt 0 ]; do
		case $1 in
		-name | -tools | -under | -uses | -ttl | -renew-before) ;;
		*) die "WRIT_GATE_GRANT: \"$1\" is not one of -name -tools -under -uses -ttl -renew-before" ;;
		esac
		case $seen in *" $1 "*) die "WRIT_GATE_GRANT gives $1 twice" ;; esac
		[ $# -ge 2 ] || die "WRIT_GATE_GRANT: $1 has no value"
		seen="$seen$1 "
		case $1 in -name) name=$2 ;; -uses) uses=$2 ;; esac
		shift 2
	done
	# Another name would leave the old any-tool session grant in force until
	# it expires, up to 24 hours.
	[ "$name" = session ] || die "WRIT_GATE_GRANT must keep -name session"
	case $uses in '' | *[!0-9]*) die "WRIT_GATE_GRANT must set -uses to a number above 0; without it, or with 0, the grant has no limit" ;; esac
	[ "$uses" -gt 0 ] || die "WRIT_GATE_GRANT must set -uses to a number above 0; 0 means no limit"
	case $uses in 0*) die "WRIT_GATE_GRANT: -uses must not start with 0, which Go reads as octal" ;; esac
}

# as_gate CMD...: run CMD as the gate's account, with the fixed PATH and
# without root's terminal.
as_gate() {
	sudo -u "$GATE_USER" env -i PATH="$PATH" HOME="$STATE" WRIT_HOME="$GATE_HOME" "$@" </dev/null
}

# plist LABEL INTERVAL ARG...: a LaunchDaemon run as the gate user. INTERVAL 0
# keeps it alive; otherwise it runs every INTERVAL seconds.
plist() {
	label=$1 interval=$2
	shift 2
	args=''
	for a in "$BIN" "$@"; do args="$args<string>$a</string>"; done
	run='<key>KeepAlive</key><true/>'
	[ "$interval" -eq 0 ] || run="<key>StartInterval</key><integer>$interval</integer>"
	cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$label</string>
<key>UserName</key><string>$GATE_USER</string><key>GroupName</key><string>$GATE_USER</string>
<key>ProgramArguments</key><array>$args</array>
<key>EnvironmentVariables</key><dict><key>WRIT_HOME</key><string>$GATE_HOME</string><key>HOME</key><string>$STATE</string></dict>
<key>Umask</key><integer>63</integer><key>RunAtLoad</key><true/>$run
<key>StandardOutPath</key><string>$LOG_DIR/$label.log</string><key>StandardErrorPath</key><string>$LOG_DIR/$label.log</string>
</dict></plist>
EOF
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

# expect_dir DIR OWNER:GROUP MODE: a tripwire for a live install, not a
# repair.
expect_dir() {
	{ [ -d "$1" ] && [ ! -L "$1" ]; } || die "$1 is missing or not a directory; uninstall, then install"
	got=$(stat -f '%Su:%Sg %Lp' "$1")
	[ "$got" = "$2 $3" ] || die "$1 is $got, not $2 $3; uninstall, then install"
	[ -z "$(find "$1" -maxdepth 0 -acl)" ] || die "$1 carries an ACL; uninstall, then install"
}

# attr KIND NAME: one attribute of the gate's account (Users) or group
# (Groups). dscl prints an attribute with no standard name, such as IsHidden,
# with a dsAttrTypeNative: prefix.
attr() {
	dscl . -read "/$1/$GATE_USER" "$2" 2>/dev/null | sed -n -e "s/^$2: //p" -e "s/^dsAttrTypeNative:$2: //p"
}

# bootout_wait: stop both daemons, and wait until launchd has let them go.
bootout_wait() {
	for l in $LABELS; do
		launchctl bootout "system/$l" 2>/dev/null || true
		i=0
		while launchctl print "system/$l" >/dev/null 2>&1; do
			[ $i -lt 20 ] || die "launchd still has system/$l"
			sleep 0.2
			i=$((i + 1))
		done
	done
}

# stop_gate: remove the gate's crontab, so cron cannot start it again, stop
# its daemons and any launchd domain of its own, then kill everything running
# as its uid, STOP first so nothing can fork between the two.
stop_gate() {
	crontab -u "$GATE_USER" -r 2>/dev/null || true
	launchctl bootout "user/$GATE_ID" 2>/dev/null || true
	bootout_wait
	i=0
	while pgrep -U "$GATE_ID" >/dev/null; do
		[ $i -lt 20 ] || die "processes still run as uid $GATE_ID: $(pgrep -U "$GATE_ID" | tr '\n' ' ')"
		pkill -STOP -U "$GATE_ID" 2>/dev/null || true
		pkill -KILL -U "$GATE_ID" 2>/dev/null || true
		sleep 0.2
		i=$((i + 1))
	done
}

# remove_state: delete /var/db/writ without root walking it, since a folder
# swapped for a symbolic link mid-walk would aim root's rm elsewhere. The
# gate's own account empties home and run, so a swap can only aim it at what
# the gate could delete anyway. Root then removes the two log files and the
# four folders by name. If anything is left, such as a file another user put
# there, the whole folder is moved aside, closed to everyone but root.
remove_state() {
	[ -e "$STATE" ] || [ -L "$STATE" ] || return 0
	if dscl . -read "/Users/$GATE_USER" >/dev/null 2>&1; then
		for d in "$GATE_HOME" "$RUN_DIR"; do
			# shellcheck disable=SC2016 # expanded by the gate's sh, not here
			as_gate /bin/sh -c 'cd "$1" && { chflags -R nouchg,nouappnd . ; rm -rf ./* ./.[!.]* ./..?* ; }' sh "$d" 2>/dev/null || true
		done
	fi
	for l in $LABELS; do rm -f "$LOG_DIR/$l.log"; done
	rmdir "$GATE_HOME" "$RUN_DIR" "$LOG_DIR" "$STATE" 2>/dev/null || true
	[ -e "$STATE" ] || [ -L "$STATE" ] || return 0
	left=/var/db/writ-leftover-$(date -u +%Y%m%dT%H%M%SZ)-$$
	[ ! -e "$left" ] || die "$left exists"
	mv "$STATE" "$left"
	{ [ -d "$left" ] && [ ! -L "$left" ]; } || die "$left is not a directory"
	chown root:wheel "$left"
	chmod 700 "$left"
	echo "writ-gate-macos: $STATE held files the gate could not delete; moved it to $left, root only. Inspect it by name, as root, without following links or extracting anything from it." >&2
}

install_gate() {
	src=$1 want=$2
	[ -f "$src" ] || die "no binary at $src"
	[ -n "$want" ] || { [ ! -L "$src" ] && [ "$(stat -f %Su "$src")" = root ]; } || die "--no-checksum takes only a root-owned file that is not a symbolic link"
	if [ -n "$want" ]; then
		case $want in *[!0-9a-f]*) die "SHA256 must be 64 lowercase hex digits" ;; esac
		[ ${#want} -eq 64 ] || die "SHA256 must be 64 lowercase hex digits"
	fi

	# Every check that can refuse runs before anything is created.
	live=''
	if dscl . -read "/Users/$GATE_USER" >/dev/null 2>&1; then
		[ "$(attr Users UniqueID)" = "$GATE_ID" ] || die "$GATE_USER exists with uid $(attr Users UniqueID), not $GATE_ID"
		[ "$(attr Users PrimaryGroupID)" = "$GATE_ID" ] || die "$GATE_USER exists with primary group $(attr Users PrimaryGroupID), not $GATE_ID"
		[ "$(attr Users UserShell)" = /usr/bin/false ] || die "$GATE_USER exists with shell $(attr Users UserShell), not /usr/bin/false"
		[ "$(attr Users IsHidden)" = 1 ] || die "$GATE_USER exists and is not hidden"
		[ "$(attr Users Password)" = '*' ] || die "$GATE_USER exists with password field \"$(attr Users Password)\", not \"*\""
		[ "$(attr Groups PrimaryGroupID)" = "$GATE_ID" ] || die "group $GATE_USER has gid $(attr Groups PrimaryGroupID), not $GATE_ID"
		[ -z "$(attr Groups GroupMembership)" ] || die "group $GATE_USER has members: $(attr Groups GroupMembership)"
		expect_dir "$STATE" root:wheel 755
		expect_dir "$GATE_HOME" "$GATE_USER:$GATE_USER" 700
		expect_dir "$RUN_DIR" "$GATE_USER:$GATE_USER" 755
		expect_dir "$LOG_DIR" root:wheel 755
		live=1
	else
		{ [ ! -e "$STATE" ] && [ ! -L "$STATE" ]; } || die "$STATE exists with no $GATE_USER account; archive and remove it first with: sudo /bin/bash $0 uninstall"
		! dscl . -read "/Groups/$GATE_USER" >/dev/null 2>&1 || die "a group $GATE_USER exists with no account $GATE_USER; remove it or find out who made it"
		uids=$(dscl . -search /Users UniqueID "$GATE_ID") || die "could not search the accounts for uid $GATE_ID"
		[ -z "$uids" ] || die "uid $GATE_ID is taken"
		gids=$(dscl . -search /Groups PrimaryGroupID "$GATE_ID") || die "could not search the groups for gid $GATE_ID"
		[ -z "$gids" ] || die "gid $GATE_ID is taken"
		! pgrep -U "$GATE_ID" >/dev/null || die "processes run as uid $GATE_ID with no account $GATE_USER"
		[ ! -e "/usr/lib/cron/tabs/$GATE_USER" ] || die "a crontab for $GATE_USER exists, /usr/lib/cron/tabs/$GATE_USER; remove it first"
		[ -z "$(find /usr/lib/cron/jobs -user "$GATE_ID" 2>/dev/null)" ] || die "at jobs owned by uid $GATE_ID exist in /usr/lib/cron/jobs; remove them first"
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

	# From here on a failure or an interruption removes what this run created
	# (rollback). A failed reinstall keeps the account and state it found, but
	# not the binary and plists it replaced.
	made_dirs='' made_tmp='' made_bin='' made_user='' made_daemons=''
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

	if [ -z "$live" ]; then
		made_user=1
		dscl . -create "/Groups/$GATE_USER"
		for k in "PrimaryGroupID:$GATE_ID" "RealName:Writ gate" "Password:*"; do
			dscl . -create "/Groups/$GATE_USER" "${k%%:*}" "${k#*:}"
		done
		dscl . -create "/Users/$GATE_USER"
		for k in "UniqueID:$GATE_ID" "PrimaryGroupID:$GATE_ID" "UserShell:/usr/bin/false" \
			"NFSHomeDirectory:$STATE" "RealName:Writ gate" "Password:*" "IsHidden:1"; do
			dscl . -create "/Users/$GATE_USER" "${k%%:*}" "${k#*:}"
		done
		echo "created $GATE_USER ($GATE_ID)"
		# A fresh tree, in /var/db, which root owns: nothing in it predates
		# this run. The log folder stays root's, since launchd opens the
		# logs as root.
		install -d -o root -g wheel -m 0755 "$STATE"
		install -d -o "$GATE_USER" -g "$GATE_USER" -m 0700 "$GATE_HOME"
		install -d -o "$GATE_USER" -g "$GATE_USER" -m 0755 "$RUN_DIR"
		install -d -o root -g wheel -m 0755 "$LOG_DIR"
	fi
	chmod -h -N "$LOG_DIR"
	for l in $LABELS; do
		rm -f "$LOG_DIR/$l.log"
		: >"$LOG_DIR/$l.log"
		chown -h "$GATE_USER:$GATE_USER" "$LOG_DIR/$l.log"
		chmod -h 0640 "$LOG_DIR/$l.log"
	done

	as_gate "$BIN" init
	echo "standing grant: $GRANT_ARGS"
	# shellcheck disable=SC2086 # GRANT_ARGS is a word list on purpose
	as_gate "$BIN" $GRANT_ARGS

	[ -n "$live" ] || made_daemons=1
	# shellcheck disable=SC2086
	plist org.writ.renew 900 $GRANT_ARGS >/Library/LaunchDaemons/org.writ.renew.plist
	plist org.writ.gate 0 serve -socket "$SOCKET" >/Library/LaunchDaemons/org.writ.gate.plist
	bootout_wait
	# A stopped gate leaves its socket file; remove it, so the wait below
	# sees the new gate's socket and not the old one.
	rm -f "$SOCKET"
	for l in $LABELS; do
		chown root:wheel "/Library/LaunchDaemons/$l.plist"
		chmod 0644 "/Library/LaunchDaemons/$l.plist"
		plutil -lint "/Library/LaunchDaemons/$l.plist" >/dev/null
		launchctl enable "system/$l"
		launchctl bootstrap system "/Library/LaunchDaemons/$l.plist"
	done

	i=0
	while [ ! -S "$SOCKET" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
	[ -S "$SOCKET" ] || die "the gate did not open $SOCKET; see $LOG_DIR/org.writ.gate.log"
	trap - EXIT INT TERM HUP
	ls -ld "$STATE" "$GATE_HOME" "$RUN_DIR" "$SOCKET" "$LOG_DIR" "$LIBEXEC" "$BIN"
	echo "gate listening on $SOCKET as $GATE_USER; set WRIT_HOOK_SOCKET=$SOCKET in the hooks"
}

# rollback runs when install exits early. It removes only what this run
# created, the fresh state through the same remove_state as uninstall.
# shellcheck disable=SC2329 # run by the EXIT trap in install_gate
rollback() {
	rc=$?
	[ "$rc" -ne 0 ] || return 0
	trap - INT TERM HUP
	echo "writ-gate-macos: install failed; undoing what this run created" >&2
	if [ -n "$made_daemons" ]; then
		for l in $LABELS; do rm -f "/Library/LaunchDaemons/$l.plist"; done
	fi
	if [ -n "$made_user" ]; then
		stop_gate
		remove_state
		dscl . -delete "/Users/$GATE_USER" 2>/dev/null || true
		dscl . -delete "/Groups/$GATE_USER" 2>/dev/null || true
		rm -f "/usr/lib/cron/tabs/$GATE_USER"
	fi
	[ -z "$made_tmp" ] || rm -f "$made_tmp"
	[ -z "$made_bin" ] || rm -f "$BIN"
	for d in $made_dirs; do
		rmdir "$d" 2>/dev/null || true
	done
	echo "writ-gate-macos: undone" >&2
	exit "$rc"
}

uninstall_gate() {
	purge=$1
	stop_gate
	for l in $LABELS; do rm -f "/Library/LaunchDaemons/$l.plist"; done
	if [ -z "$purge" ] && [ -d "$STATE" ] && dscl . -read "/Users/$GATE_USER" >/dev/null 2>&1; then
		# The gate's account makes the archive, so it holds nothing the gate
		# could not read; root only creates the file, mode 600, and writes
		# the stream into it.
		archive=/var/db/writ-archive-$(date -u +%Y%m%dT%H%M%SZ)-$$.tar
		(umask 077 && set -C && : >"$archive") || die "could not create $archive"
		if ! as_gate tar -cf - -C /var/db writ >"$archive" || ! tar -tf "$archive" >/dev/null; then
			rm -f "$archive"
			die "tar could not archive $STATE as $GATE_USER, so nothing was removed; fix what it names, or run uninstall --purge to delete it without an archive"
		fi
		tar -tf "$archive" | grep -q '^writ/home/' || die "$archive holds no writ/home; $STATE was not removed"
		echo "archived $STATE to $archive (root only); to list it: sudo tar -tvf $archive"
		echo "to read the audit record: sudo tar -xOf $archive writ/home/claude/audit.jsonl"
	fi
	remove_state
	dscl . -delete "/Users/$GATE_USER" 2>/dev/null || true
	dscl . -delete "/Groups/$GATE_USER" 2>/dev/null || true
	rm -f "/usr/lib/cron/tabs/$GATE_USER"
	rm -f "$BIN"
	rmdir "$LIBEXEC" 2>/dev/null || true
	echo "removed the daemons, the crontab, $STATE, $BIN, and $GATE_USER"
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
	uninstall)
		case "${2:-}" in
		'') uninstall_gate '' ;;
		--purge) uninstall_gate 1 ;;
		*) die "uninstall [--purge]" ;;
		esac
		;;
	*) die "usage: install BINARY SHA256 | install --no-checksum BINARY | uninstall [--purge]" ;;
	esac
}

# Bash reads a script as it runs, so this one line runs all of it and exits
# before anything appended to the file could be read.
main "$@"; exit
