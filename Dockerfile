FROM golang:latest as gobuilder
ENV CGO_ENABLED=0
COPY . /vault-hunter
RUN cd /vault-hunter && go build -o vault-hunter ./cmd/vault-hunter/main.go