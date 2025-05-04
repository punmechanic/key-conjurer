FROM golang:1.24 AS build
RUN mkdir /sources
WORKDIR /sources
COPY ./ ./
ENV GOOS=linux GOARCH=amd64 CGO_ENABLED=0
RUN go build -tags lambda.norpc -o webserver webserver/main.go

FROM public.ecr.aws/lambda/provided:al2
COPY --from=build /sources/webserver /webserver
ENTRYPOINT ["/webserver"]
