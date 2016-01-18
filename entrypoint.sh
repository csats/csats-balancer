#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

mkfifo /var/log/nginx/access.log
mkfifo /var/log/nginx/error.log
cat /var/log/nginx/access.log &
cat /var/log/nginx/error.log &
/controller 2>&1
