# Build the manager binary
FROM golang:1.17 as builder

WORKDIR /workspace

#ENV http_proxy=http://defraprx-fihelprx.glb.nsn-net.net:8080
#ENV https_proxy=http://defraprx-fihelprx.glb.nsn-net.net:8080
#ENV HTTP_PROXY=http://defraprx-fihelprx.glb.nsn-net.net:8080
#ENV HTTPS_PROXY=http://defraprx-fihelprx.glb.nsn-net.net:8080
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum


# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source

COPY adcs-sim/ adcs-sim/
COPY e2e/ 2e2/
RUN	mkdir -p /usr/local/adcs-sim

# Build

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o manager adcs-sim/main.go

FROM gcr.io/distroless/static:nonroot 
WORKDIR /
COPY --from=builder /workspace/manager .
COPY --from=builder /workspace/adcs-sim /usr/local/bin/

COPY --from=builder /workspace/adcs-sim/ca /usr/local/adcs-sim/ca
COPY --from=builder /workspace/adcs-sim/templates /usr/local/adcs-sim/templates
COPY --from=builder /workspace/manager /usr/local/adcs-sim/manager

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/adcs-sim/manager"]

