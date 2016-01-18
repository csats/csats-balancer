# Adapted from Kubernetes' nginx-alpha, so keep this copyright around.
#
# Copyright 2015 The Kubernetes Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM debian:jessie
COPY nginx/nginx /usr/bin/nginx
COPY nginx/default.conf /etc/nginx/nginx.conf
RUN apt-get update && apt-get install -y libssl1.0.0 curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/log/nginx && mkdir -p /var/cache/nginx
COPY controller/controller /
COPY entrypoint.sh /entrypoint.sh
CMD ["/controller"]
