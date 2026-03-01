FROM golang:1.24-alpine AS build
WORKDIR /app

# On récupère les dépendances (dont github.com/lib/pq)
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# On compile le bot
RUN CGO_ENABLED=0 go build -o /out/sentinel ./cmd/sentinel

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel

WORKDIR /app

# On récupère l'exécutable
COPY --from=build /out/sentinel /app/sentinel

# IMPORTANT : On copie ton VRAI fichier config, pas l'exemple !
COPY config.yaml /app/config.yaml

# On enlève la variable DATABASE_PATH qui forçait le .db
# Le bot lira l'URL directement dans ton config.yaml

USER sentinel
ENTRYPOINT ["/app/sentinel"]
