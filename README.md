# csats-balancer

This project aims to be a pretty good HTTPS Load Balancer for Kubernetes. It is dynamically configurable using the
Ingress object. It's also designed to be easily customizable.

Features:

1. Load Balancing
2. Sticky Sessions
3. SSL Termination

## Usage

SSL is currently required. When csats-balancer boots, it will expect there to be a keyfile at `/ssl/key.pem` and a
certchain file at `/ssl/certchain.pem`. These filenames jive nicely with the ones generated by
[kubernetes-letsencrypt](https://github.com/iameli/kubernetes-letsencrypt).

## Development

You'll want to do something like this in order to get a service account token and test.

```
mkdir serviceaccount
kubectl exec some-running-pod cat /var/run/secrets/kubernetes.io/serviceaccount/token > serviceaccount/token
kubectl exec some-running-pod cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt > serviceaccount/ca.crt
docker run --rm --name nginx-dev \
    -v $(pwd)/serviceaccount:/var/run/secrets/kubernetes.io/serviceaccount \
    -v $(pwd)/ssl:/ssl \
    -e KUBERNETES_SERVICE_HOST=mission-control.dandiprat.industries \
    -e KUBERNETES_SERVICE_PORT=443 -p 80:80 \
    docker.io/csats/csats-balancer
```
