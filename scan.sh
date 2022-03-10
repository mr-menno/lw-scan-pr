#!/bin/sh
IMAGE=$(echo $1 | cut -f1 -d:)
TAG=$(echo $1 | cut -f2 -d:)
echo "Scanning:"
echo "  image=$IMAGE"
echo "  tag=$TAG"
echo $LW_ACCESS_TOKEN
./lw-scanner --help