FROM golang:1.19-alpine as build
RUN mkdir -p /sources /bin
COPY ./ /sources/
WORKDIR /sources
RUN GOTOOLCHAIN=1.19 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags lambda.norpc -o /bin/bootstrap github.com/riotgames/key-conjurer/lambda/list_applications

FROM public.ecr.aws/lambda/provided:al2023
COPY --from=build /bin/bootstrap ./main
ENTRYPOINT ["./main"]
