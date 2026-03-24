#!/bin/sh

# Warn about deprecation of GUACD_LOG_LEVEL
if [ -n "$GUACD_LOG_LEVEL" ]; then
    echo "WARNING: The GUACD_LOG_LEVEL environment variable has been deprecated in favor of the LOG_LEVEL environment variable. Please migrate your configuration when possible." >&2
fi

# Graceful shutdown handler: send SIGTERM to all child processes first so they
# can complete any pending S3 recording uploads, then wait briefly before exit.
_term() {
    echo "Received SIGTERM, forwarding to child processes..." >&2
    kill -TERM -- -$$ 2>/dev/null
    sleep 5
    exit 0
}
trap _term TERM

# Listen on 0.0.0.0:4822, logging messages at the info level. Allow log level
# to be overridden with LOG_LEVEL, and other behavior to be overridden with
# additional command-line options passed to Docker.
/opt/guacamole/sbin/guacd -f -b 0.0.0.0 -L "${LOG_LEVEL:-${GUACD_LOG_LEVEL:-info}}" "$@" &
wait $!
