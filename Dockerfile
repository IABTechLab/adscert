FROM golang:1.16.5 as builder
COPY . /src
WORKDIR /src
RUN GRPC_HEALTH_PROBE_VERSION=v0.3.1 && \
    wget -qO/bin/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64 && \
    chmod +x /bin/grpc_health_probe
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build ./cmd/server

FROM alpine
WORKDIR /app
RUN apk --no-cache add ca-certificates
COPY --from=builder /src/server .
COPY --from=builder /bin/grpc_health_probe /bin/grpc_health_probe

ENV LOGLEVEL=""
ENV ORIGIN=""
ENV DOMAIN_CHECK_INTERVAL=""
ENV DOMAIN_RENEWAL_INTERVAL=""
ENV PRIVATE_KEY=""
