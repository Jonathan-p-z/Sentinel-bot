FROM golang:1.21-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -o /out/sentinel ./cmd/sentinel

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel
WORKDIR /app
COPY --from=build /out/sentinel /app/sentinel
COPY config.yaml.example /app/config.yaml
VOLUME ["/data"]
ENV DATABASE_PATH=/data/sentinel.db
USER sentinel
ENTRYPOINT ["/app/sentinel"]
