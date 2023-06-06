build:
	go build -o bin/netvuln main.go

run:
	go run main.go

test:
	go test

lint:
	golangci-lint run