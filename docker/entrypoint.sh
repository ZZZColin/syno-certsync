#!/bin/bash
# Runs certsync jobs forever, every SYNC_INTERVAL_HOURS.
# Jobs: one CLI argument line per row in /config/jobs.txt (blank lines and # comments ignored;
# quote wildcard domains, e.g. -d '*.example.com'), or a single job from the SYNC_ARGS env var.
set -u
cd /app

run_jobs() {
  if [ -f /config/jobs.txt ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      case "$line" in ""|\#*) continue;; esac
      echo "[$(date -Iseconds)] certsync $line"
      eval "python -m syno_certsync $line" || echo "job failed: $line"
    done < /config/jobs.txt
  elif [ -n "${SYNC_ARGS:-}" ]; then
    echo "[$(date -Iseconds)] certsync $SYNC_ARGS"
    eval "python -m syno_certsync $SYNC_ARGS" || echo "job failed: $SYNC_ARGS"
  else
    echo "No /config/jobs.txt and no SYNC_ARGS set; nothing to do."
  fi
}

if [ "${1:-}" = "once" ]; then run_jobs; exit 0; fi
if [ $# -gt 0 ]; then exec python -m syno_certsync "$@"; fi

# Exit promptly on `docker stop` (bash as PID 1 ignores signals while a foreground sleep runs).
trap 'exit 0' TERM INT
while true; do
  run_jobs
  sleep "$(( ${SYNC_INTERVAL_HOURS:-24} * 3600 ))" &
  wait $!
done
