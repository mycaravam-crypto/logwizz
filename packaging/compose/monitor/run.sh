#!/bin/sh
# logwizz only writes events to stdout. Keep them there for `docker logs` and copy them to
# the file the notifier container reads, rotating it so it cannot grow without limit.
/usr/local/bin/logwizz --config /etc/logwizz/portable.toml | awk -v f=/data/events.jsonl -v max="${EVENT_FILE_MAX_LINES:-20000}" '
    { print; fflush(); print >> f; fflush(f)
      if (++n >= max) { close(f); system("mv " f " " f ".1"); n = 0 } }'
