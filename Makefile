.PHONY: api assets build cmd configs deployments docs examples githooks init interna pkg scripts test third_party tools web website

init:
ifneq (, $(wildcard ./go.mod))
	$(error "Cannot make init, go.mod already exists")
endif
	@go mod init $$(git remote get-url origin | sed -e 's/.*:\/\/\(.*\)$$/\1/' -e 's/\.git$$//')
	@touch .env
	@touch go.sum
	@printf "// Main package is the entrypoint for the program\npackage main\n\nfunc main() {}\n" > cmd/main.go
	@printf "package main_test\n" > cmd/main_test.go

setup:
	go mod tidy

cert:
	@mkdir -p ./.cert
	@openssl genrsa -out ./.cert/id_rsa 4096
	@openssl rsa -in ./.cert/id_rsa -pubout -out ./.cert/id_rsa.pub

test:
	@mkdir -p .test
	@go test -coverprofile=./.test/coverage.out ./...

lint:
	@golangci-lint run -c tools/.golangci.yml
