# Lacework Scanner

## Requirements
This action leverages the Lacework vulnerability scanner.  If leveraged in a pull request, it will also comment in the pull requests
on vulnerabilities.

## Usage

Image name and tag and either be split up, or combined, and support multiple tags input (only first tag is scanned)

Valid examples:
* IMAGE_TAG=ghcr.io/repo/image:latest
* IMAGE_NAME=ghcr.io/repo/image:latest
* IMAGE_NAME=ghcr.io/repo/image IMAGE_TAG=latest

`FAIL_POLICY` can be either `true` or `false` and will decide if failing on a Lacework protocol should happen.

`FAIL_SEVERITY` is the minimum threshold at which to fail.  Options are `critical`, `high`, `medium`, `low`, `info`, and can
optionally be affixed with `-fixable` to require the threshold to have fixable vulnerabilities.  Example would be `high-fixable`.

```
- name: Lacework Scanner
  id: lacework
  uses: ./
  with:
    IMAGE_NAME: <ghcr.io/repo/image>
    IMAGE_TAG: <latest|pr-2|...>
    FAIL_POLICY: true
    FAIL_SEVERITY: medium-fixable
```

## Example

Example GitHub Actions workflow:

```
name: "Build and Scan"

on:
  pull_request:
  push:
  - main

jobs:
  build-and-scan:
    runs-on: ubuntu-latest

# ensure LW_ACCESS_TOKEN and LW_ACCOUNT_NAME are configured
    env:
      LW_ACCESS_TOKEN: ${{ secrets.LW_ACCESS_TOKEN }}
      LW_ACCOUNT_NAME: ${{ secrets.LW_ACCOUNT_NAME }}
      REGISTRY: ghcr.io
      IMAGE_NAME: ${{ github.repository }}

# Checkout code
    steps:
    - name: Checkout
      uses: actions/checkout@v2
 
 # Login to container registry, if not a pull request
    - name: Login to Container Registry
      if: github.event_name != 'pull_request'
      uses: docker/login-action@v1
      with:
        registry: ghcr.io
        username: ${{ secrets.DOCKER_USERNAME }}
        password: ${{ secrets.DOCKER_PASSWORD }}

# Automatically Determine tags and labels for Docker
    - name: Extract metadata (tags, labels) for Docker
      id: meta
      uses: docker/metadata-action@v3
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}/test-image
        tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=sha

# Build Docker Container only for Scanning            
    - name: Build Only
      uses: docker/build-push-action@v2
      with:
        context: .
        push: false
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}

# Scan using Lacework Scanner
    - name: Lacework Scanner
      id: lacework
      uses: ./
      with:
        IMAGE_TAG: ${{ steps.meta.outputs.tags }}
        FAIL_POLICY: true
        FAIL_SEVERITY: medium-fixable

# Build and Push docker image, skip if PR
    - name: Build and Push
      uses: docker/build-push-action@v2
      with:
        context: .
        push: ${{ github.event_name != 'pull_request' }}
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
```