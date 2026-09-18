.PHONY: build test vet run docker clean

build:
	go build -o guardbridge ./cmd/guardbridge

test:
	go test ./...

vet:
	go vet ./...

run:
	go run ./cmd/guardbridge -config config.example.yaml

docker:
	docker build -t guardbridge:latest .

clean:
	rm -f guardbridge
