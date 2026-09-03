# syntax=docker/dockerfile:1
FROM golang:1.23-alpine AS builder
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ip-intelligence ./cmd/server

FROM scratch
COPY --from=builder /out/ip-intelligence /ip-intelligence
COPY data/rules /data/rules
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/ip-intelligence"]
