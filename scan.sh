#!/bin/sh
which docker
docker ps
IMAGE=$(echo $1 | cut -f1 -d:)
TAG=$(echo $1 | cut -f2 -d:)
echo "Scanning:"
echo "  image=$IMAGE"
echo "  tag=$TAG"
./lw-scanner evaluate $IMAGE $TAG --policy --fail-on-violation-exit-code 1 -v=false > lw-scan-results.json