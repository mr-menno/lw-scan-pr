#!/bin/sh
IMAGE=$(echo $1 | cut -f1 -d:)
TAG=$(echo $1 | cut -f2 -d:)
echo "Scanning:"
echo "  image=$IMAGE"
echo "  tag=$TAG"
./lw-scanner evaluate $IMAGE $TAG --policy --fail-on-violation-exit-code 1 -v=false --html --html-file lw-scan-result.html > lw-scan-results.json
jq '.' lw-scan-result.json