FROM golang:1.17-alpine AS builder

RUN apk --no-cache add git ca-certificates

WORKDIR /go/src/github.com/Max-Sum/fcbreak
COPY . .

RUN cd cmd/client && CGO_ENABLED=0 go build \
 && cd cmd/server && CGO_ENABLED=0 go build

# Server Image
FROM scratch as server

WORKDIR /app
COPY --from=builder \
     /go/src/github.com/Max-Sum/fcbreak/cmd/server server
ENTRYPOINT [ "/app/client" ]
CMD "-l" ":8707"

# Client Image
FROM alpine as client

WORKDIR /app
COPY --from=builder \
     /go/src/github.com/Max-Sum/fcbreak/cmd/client client

ENTRYPOINT [ "/app/client" ]
CMD "-c" "config.ini"
