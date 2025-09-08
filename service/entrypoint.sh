#!/bin/sh

python3 /service/main.py
# mkdir -p "$RESULTDIR"

# expiry=$((13*60))
# while [ 1 ]; do
# 	reftime="$(($(date +%s)-$expiry))"
# 	echo "[FILE CLEANUP] @ $(date +%T)"
# 	cleaner "$RESULTDIR" "$reftime" &> /tmp/cleaner-log
# 	sleep 70
# done &

# ncat --keep-open --listen -p 9000 --max-conns 4000 \
# --no-shutdown --wait 10s --exec /service/build/stldoctor
