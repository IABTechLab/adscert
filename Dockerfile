FROM golang:1.16.5 as builder
COPY . /src
WORKDIR /src
RUN go mod download
RUN CGO_ENABLED=0 go build ./cmd/server

FROM alpine
RUN apk --no-cache add ca-certificates
COPY --from=builder /src/cmd/server/ .

EXPOSE 3000
ENTRYPOINT [ "./server" ]
