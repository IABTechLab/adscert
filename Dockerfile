FROM golang:1.17 as builder
COPY . /src
WORKDIR /src
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build .
RUN CGO_ENABLED=0 GOOS=linux go build ./cmd/server

FROM alpine
WORKDIR /app
RUN apk --no-cache add ca-certificates
COPY --from=builder /src/adscert .
COPY --from=builder /src/server .

ENV LOGLEVEL=""
ENV ORIGIN=""
ENV DOMAIN_CHECK_INTERVAL=""
ENV DOMAIN_RENEWAL_INTERVAL=""
ENV PRIVATE_KEY=""

EXPOSE 3000 4000 5000
