#!/bin/bash
# E-mail traffic generator (mvp.md §3.1): swaks sends SMTP to Postfix on server-b;
# IMAP pulls from Dovecot. Attachment sizes vary 10 KB-5 MB.
# Usage: email.sh <server_ip> <duration_seconds>
set -euo pipefail
SERVER="${1:?server ip required}"
DURATION="${2:-120}"
END=$((SECONDS + DURATION))

i=0
while [ $SECONDS -lt $END ]; do
  # 10 KB, 100 KB, 1 MB, 5 MB rotating attachment sizes.
  case $((i % 4)) in
    0) SIZE=10240 ;;
    1) SIZE=102400 ;;
    2) SIZE=1048576 ;;
    3) SIZE=5242880 ;;
  esac
  ATTACH="/tmp/attach_${SIZE}.bin"
  head -c "$SIZE" /dev/urandom > "$ATTACH"

  swaks --to labuser@server-b --from sender@client-a \
        --server "$SERVER" --port 25 \
        --attach "@$ATTACH" \
        --header "Subject: lab-mail-$i" >/dev/null

  # IMAP fetch cycle (Dovecot, port 143).
  python3 - "$SERVER" <<'PY'
import imaplib, ssl, sys
host = sys.argv[1]
# Dovecot requires TLS for password login from gateway-hosted clients.
# The isolated lab uses its locally generated certificate.
m = imaplib.IMAP4_SSL(host, 993, ssl_context=ssl._create_unverified_context())
m.login("labuser", "labpass")
m.select("INBOX")
typ, data = m.search(None, "ALL")
for num in (data[0].split()[-3:] if data and data[0] else []):
    m.fetch(num, "(RFC822)")
m.logout()
PY

  i=$((i + 1))
  sleep 5
done
