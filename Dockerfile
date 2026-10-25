# WebTAK Server in Docker:  docker compose up -d   (then open https://<host>:8443/)
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /webtak-server .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -H -u 1000 webtak && mkdir /data && chown webtak /data
COPY --from=build /webtak-server /usr/local/bin/webtak-server
USER webtak
VOLUME /data
EXPOSE 8088 8089 8443 8080 8446 9000
ENTRYPOINT ["webtak-server", "-service", "-data", "/data"]
