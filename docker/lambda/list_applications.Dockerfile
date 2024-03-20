FROM golang:1.19-alpine as build
RUN mkdir -p /sources /bin
COPY ./ /sources/
WORKDIR /sources
RUN GOTOOLCHAIN=1.19 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags lambda.norpc -o /bin/bootstrap github.com/riotgames/key-conjurer/lambda/list_applications

FROM public.ecr.aws/lambda/provided:al2023
RUN dnf install unzip -y
# Install the Vault Lambda extension.
# This enables us to avoid having to interact with Vault in our code; instead, we can pull the secrets from a file, and write them into the env.
RUN mkdir -p /opt/extensions/
RUN curl --silent https://releases.hashicorp.com/vault-lambda-extension/0.5.0/vault-lambda-extension_0.5.0_linux_amd64.zip --output vault-lambda-extension.zip && \
    unzip vault-lambda-extension.zip && \
    mv extensions/vault-lambda-extension /opt/extensions/vault

COPY --from=build /bin/bootstrap /main
COPY docker/lambda/run.sh /run.sh
CMD ["/run.sh"]
