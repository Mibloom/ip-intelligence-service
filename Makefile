.PHONY: build test data data-dbip data-cloud data-threat data-maxmind docker-build run

build:
	go build -trimpath -o bin/ip-intelligence ./cmd/server

test:
	go test ./...

data: data-dbip data-cloud data-threat

data-dbip:
	./scripts/update-dbip.sh

data-cloud:
	./scripts/update-cloud-ranges.sh

data-threat:
	./scripts/update-threat-ranges.sh

data-maxmind:
	./scripts/update-maxmind.sh

docker-build:
	docker build -t ip-intelligence:local .

run:
	go run ./cmd/server
