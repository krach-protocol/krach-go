#!/bin/bash

RUN_COUNT=100
FAIL_COUNT=0

for i in `seq 1 $RUN_COUNT`; do
  #echo "Executing iteration $i"
  OUT=$(go test -timeout 30s)
  RC=$?

  if [ "$RC" != "0" ]; then
    FAIL_COUNT=$((FAIL_COUNT+1))
    echo "$OUT"
  fi
done
FAILURE_RATE=$((FAIL_COUNT*100/RUN_COUNT))
echo "Failure rate: $FAILURE_RATE"
