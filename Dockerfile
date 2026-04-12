# Stage 1: build eBPF C program and Go binary
FROM --platform=linux/amd64 golang:1.24-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev linux-headers-amd64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Generate eBPF Go bindings from C source
RUN go generate ./bpf/

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /akash-guard ./cmd/akash-guard

# Stage 2: minimal runtime image
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /akash-guard /akash-guard

ENTRYPOINT ["/akash-guard"]
