#!/bin/sh

set -xe

PALA=pala
FASTPATH=/config/fastpath
CONFIG_PATH=${CONFIG_PATH:-${FASTPATH}/${PALA}}

start_pala() {
	exec $PALA --configPath "${CONFIG_PATH}" "$@"
}

main() {
	start_pala "$@"
}

main "$@"
