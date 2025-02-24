FROM golang:latest AS builder
WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/app

FROM arm64v8/ubuntu:latest
RUN apt-get update
RUN apt-get install -y ca-certificates curl
RUN curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_arm64/session-manager-plugin.deb" -o "session-manager-plugin.deb" \
    && dpkg -i session-manager-plugin.deb \
    && rm -f session-manager-plubin.deb

COPY --from=builder /go/bin/app /
ENTRYPOINT ["/app"]
