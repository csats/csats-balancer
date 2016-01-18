#!/bin/bash

# Hacky, sorry. I threw this together real fast. This is expecting that you'll have copied a
# serviceaccount token to ./token. It downloads certs from the csats-pizza namespace

mkdir -p ./certs
kubectl get --namespace csats-pizza secret wildcard-ssl -o json | jq -r '.data["ssl.crt"]' | base64 --decode > certs/ssl.crt
kubectl get --namespace csats-pizza secret wildcard-ssl -o json | jq -r '.data["ssl.key"]' | base64 --decode > certs/ssl.key

mkdir -p $(pwd)/conf
rm -rf conf/*
cp default.conf conf/nginx.conf

docker run \
  -e KUBERNETES_SERVICE_HOST=kube-master-west.csats.pizza \
  -e KUBERNETES_SERVICE_PORT=443 \
  -v $(pwd)/token:/var/run/secrets/kubernetes.io/serviceaccount/token \
  -v $(pwd)/certs:/certs \
  -v $(pwd)/conf:/etc/nginx \
  -v $CSATS_KEYS_REPO/kubernetes/cluster-certs/kubernetes-west/ca.pem:/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  --name csats-balancer-dev \
  -e NAMESPACE="csats-pizza" \
  --rm \
  -it \
  gcr.io/surveyadmin-001/csats-balancer
