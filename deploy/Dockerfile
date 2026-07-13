FROM golang:1.26.5-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/aegis-gateway ./cmd/gateway
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/aegis-worker ./cmd/worker
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/aegis-audit-verifier ./cmd/audit-verifier

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/aegis-gateway /aegis-gateway
COPY --from=build /out/aegis-worker /aegis-worker
COPY --from=build /out/aegis-audit-verifier /aegis-audit-verifier
USER nonroot:nonroot
ENTRYPOINT ["/aegis-gateway"]
