#!/bin/bash
# Gateway entrypoint: renders the selected profile, starts charon, waits.
# Role and profile come from the compose environment (LAB_ROLE, LAB_PROFILE).
set -euo pipefail

ROLE="${LAB_ROLE:?LAB_ROLE must be gw-a or gw-b}"
PROFILE="${LAB_PROFILE:-p01}"
PROFILES_DIR="${LAB_PROFILES_DIR:-/profiles}"

mkdir -p /etc/swanctl /var/run

# Render this role's config for the selected profile.
# gw-b is the responder: same connection, right-side addressing.
python3 - "$ROLE" "$PROFILE" "$PROFILES_DIR" <<'PY'
import pathlib, sys

sys.path.insert(0, "/")
from render import render_config

import yaml

role, profile_id, profiles_dir = sys.argv[1], sys.argv[2], sys.argv[3]
prof = None
for p in pathlib.Path(profiles_dir).glob(f"{profile_id}-*.yaml"):
    prof = yaml.safe_load(p.read_text())
    break
if prof is None:
    raise SystemExit(f"profile {profile_id} not found in {profiles_dir}")

cfg = render_config(prof, psk="lab-only-psk", role=role)
if prof["ike_version"] == 1:
    pathlib.Path("/etc/ipsec.conf").write_text(cfg)
    # IKEv1 loads via stroke; make sure no swanctl config lingers.
    pathlib.Path("/etc/swanctl/swanctl.conf").unlink(missing_ok=True)
    mode = "ipsec"
else:
    pathlib.Path("/etc/swanctl/swanctl.conf").write_text(cfg)
    # IKEv2 loads via swanctl/vici; remove the distro's stock ipsec.conf so
    # the stroke path below never fires with an unrelated config.
    pathlib.Path("/etc/ipsec.conf").unlink(missing_ok=True)
    mode = "swanctl"
print(f"[entrypoint] {role}: rendered {prof['id']} ({mode})")
PY

# Enable save-keys when the plugin exists (see Dockerfile note); else say so.
if [ -f /etc/strongswan.d/charon/save-keys.conf ]; then
  sed -i 's/load = no/load = yes/' /etc/strongswan.d/charon/save-keys.conf || true
  echo "save-keys plugin enabled"
else
  echo "WARN: save-keys plugin not present; session keys/ will be empty (M-B decrypt check will degrade loudly)" | tee /var/run/save-keys-missing
fi

# ECP DH groups (p04/p05/p11) need the openssl plugin, which Debian ships
# disabled by default; enable it before charon starts.
if [ -f /etc/strongswan.d/charon/openssl.conf ]; then
  sed -i 's/load = no/load = yes/' /etc/strongswan.d/charon/openssl.conf
  echo "openssl plugin enabled (ECP DH groups)"
fi

# IKEv2: load via swanctl/vici (reads /etc/swanctl/swanctl.conf by default).
# IKEv1: load via stroke/starter (ipsec.conf). starter owns the daemon
# lifecycle here: launching charon independently leaves starter unable to
# reliably push conns into the running daemon on this image.
if [ -f /etc/swanctl/swanctl.conf ]; then
  /usr/lib/ipsec/charon > /var/log/charon-stdout.log 2>&1 &
  sleep 2
  swanctl --load-conns || true
  swanctl --load-creds || true
else
  printf '%%any %%any : PSK "%s"\n' "${PSK:-lab-only-psk}" > /etc/ipsec.secrets
  exec /usr/lib/ipsec/starter --nofork
fi

# The runner initiates/terminates the IKE SA (lab/runner/orchestrate.py).
sleep infinity
