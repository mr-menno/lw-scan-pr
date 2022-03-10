#!/bin/sh
IMAGE=$(echo $1 | cut -f1 -d:)
TAG=$(echo $1 | cut -f2 -d:)
echo "::set-output name=IMAGE::$IMAGE"
echo "::set-output name=TAG::$TAG"
# removed html output while waitnig for bug fix.
./lw-scanner evaluate $IMAGE $TAG --policy -v=false -q -s > lw-scan-result.json
#./lw-scanner evaluate $IMAGE $TAG --policy -v=false --html --html-file lw-scan-result.html -q -s > lw-scan-result.json
# echo '{"test":"two"}' > lw-scan-result.json
ls
# jq '.' lw-scan-results.json