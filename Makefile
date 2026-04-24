.PHONY: test race cover lint tidy clean

test:
	go test ./...

race:
	go test -race ./...

cover:
	go test -race -covermode=atomic -coverprofile=cover.out ./...
	go tool cover -func=cover.out | tail -1

lint:
	go vet ./...
	golangci-lint run

tidy:
	go mod tidy

clean:
	rm -f cover.out
