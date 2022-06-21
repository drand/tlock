FROM golang:1-alpine as build

RUN apk update && apk add git
RUN git clone https://github.com/drand/drand.git

WORKDIR /go/drand

RUN go build

# Run Drand
FROM alpine
RUN apk update && apk add bash curl

WORKDIR /

# EXPOSE 5101

COPY --from=0 /go/drand/drand .
COPY local.sh local.sh

# The value here is not important when running locally
ENV DRAND_SHARE_SECRET=CF63F78CD021A2C2FA87F997C7BD1D44B77BD75DB98511110EDC6B5695DB1AA0

ENTRYPOINT [ "bash", "/local.sh" ]