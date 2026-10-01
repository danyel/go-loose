FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/go-loose ./cmd/go-loose

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/go-loose /go-loose
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/go-loose"]
