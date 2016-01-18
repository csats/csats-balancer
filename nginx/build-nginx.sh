#!/bin/bash

# We need our own version of nginx for nginx-sticky-module-ng. This makes that.
set -o errexit
set -o nounset
set -o pipefail

nginx_version="1.9.7"
nginx_sticky_version="1.2.6"

apt-get update
apt-get install -y \
  build-essential \
  curl \
  libgd2-dev \
  libncurses5-dev \
  libpcre3-dev \
  libreadline-dev \
  libssl-dev \
  libxslt1-dev \
  make

mkdir -p /build
cd /build

# built from commit c78b7dd79d0d099e359c5c4394d13c9317b9348f
curl -v -o nginx-sticky-module-ng.tar.gz \
  https://bitbucket.org/nginx-goodies/nginx-sticky-module-ng/get/$nginx_sticky_version.tar.gz
tar xzf nginx-sticky-module-ng.tar.gz
mv nginx-goodies* nginx-sticky-module

curl -v -o nginx.tar.gz "http://nginx.org/download/nginx-$nginx_version.tar.gz"
tar xzf nginx.tar.gz

cd "nginx-$nginx_version"
./configure \
  --prefix=/etc/nginx \
  --sbin-path=/usr/sbin/nginx \
  --conf-path=/etc/nginx/nginx.conf \
  --error-log-path=/var/log/nginx/error.log \
  --http-log-path=/var/log/nginx/access.log \
  --pid-path=/var/run/nginx.pid \
  --lock-path=/var/run/nginx.lock \
  --http-client-body-temp-path=/var/cache/nginx/client_temp \
  --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
  --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
  --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
  --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
  --user=root \
  --group=root \
  --with-http_ssl_module \
  --with-http_realip_module \
  --with-http_addition_module \
  --with-http_sub_module \
  --with-http_dav_module \
  --with-http_flv_module \
  --with-http_mp4_module \
  --with-http_gunzip_module \
  --with-http_gzip_static_module \
  --with-http_random_index_module \
  --with-http_secure_link_module \
  --with-http_stub_status_module \
  --with-http_auth_request_module \
  --with-threads \
  --with-stream \
  --with-stream_ssl_module \
  --with-mail \
  --with-mail_ssl_module \
  --with-file-aio \
  --with-http_v2_module \
  --with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2' \
  --with-ld-opt='-Wl,-z,relro -Wl,--as-needed' \
  --with-ipv6 \
  --add-module=../nginx-sticky-module

make
cp objs/nginx /host/nginx
