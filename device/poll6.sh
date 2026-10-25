#!/system/bin/sh
# read-only slabinfo sampler: "<n> <uptime> <active>/<total>/<slabs>"
i=0
while [ $i -lt 1500 ]; do
  u=$(cut -d' ' -f1 /proc/uptime)
  l=$(grep posix_timers_cache /proc/slabinfo)
  set -- $l
  s=$(( $3 / ${5:-31} ))
  echo "$i $u $2/$3/$s"
  i=$((i+1))
  sleep 0.2
done
