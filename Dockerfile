FROM golang:1.19-alpine AS builder

WORKDIR /go/src/github.com/Max-Sum/fcbreak

ARG GOPROXY=https://goproxy.io,direct

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build ./cmd/client \
 && CGO_ENABLED=0 go build ./cmd/server

RUN ls

# Server Image
FROM scratch as server

WORKDIR /
COPY --from=builder \
     /go/src/github.com/Max-Sum/fcbreak/server /server
EXPOSE 8707
ENTRYPOINT [ "/server" ]
CMD ["-l", ":8707"]

# Client Image
FROM scratch as client

WORKDIR /
COPY --from=builder \
     /go/src/github.com/Max-Sum/fcbreak/client /client

ENTRYPOINT [ "/client" ]
CMD ["-c", "config.ini", "-f"]
