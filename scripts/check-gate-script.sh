#!/bin/sh
# check-gate-script.sh [FILE]: fail if writ-gate-macos.sh has root walk the
# gate's state tree, which the gate could reshape under it: a recursive rm,
# chown, chmod, or chflags on any line not run through as_gate, or a find on
# the state tree that is not -maxdepth 0. Comment lines are skipped.
f=${1:-scripts/writ-gate-macos.sh}
# shellcheck disable=SC2016 # the $ names are matched as text
bad=$(grep -nE 'rm[[:space:]]+-[A-Za-z]*[rR]|(chown|chmod|chflags)[[:space:]]+(-[A-Za-z]+[[:space:]]+)*-[A-Za-z]*R|find[[:space:]].*(\$STATE|\$GATE_HOME|\$RUN_DIR|\$LOG_DIR|/var/db/writ)' "$f" |
	grep -vE '^[0-9]+:[[:space:]]*#' | grep -v 'as_gate' | grep -v -- '-maxdepth 0')
if [ -n "$bad" ]; then
	echo "root walks the gate's state tree in $f:"
	echo "$bad"
	exit 1
fi
echo "$f: no root-run recursive rm, chown, chmod, or chflags, and no find on the state tree"
