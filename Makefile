
all: nginx controller container

.PHONY: controller container push

nginx: .
	docker run -it -v $(PWD)/nginx:/host debian:jessie /host/build-nginx.sh

controller: .
	docker run -e GOPATH=/app/Godeps/_workspace -v $(PWD):/app -w /app golang go build -v -o ./controller/controller ./controller/controller.go

container: .
	docker build -t docker.io/csats/csats-balancer .

push: .
	docker push docker.io/csats/csats-balancer
