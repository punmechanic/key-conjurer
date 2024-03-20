package main

import (
	"net/url"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/riotgames/key-conjurer/internal"
	"github.com/riotgames/key-conjurer/internal/api"
	"golang.org/x/exp/slog"
)

func main() {
	oktaDomain := url.URL{
		Scheme: "https",
		Host:   os.Getenv("OKTA_HOST"),
	}

	slog.Info("running list_applications_v2 Lambda")
	service := api.NewOktaService(&oktaDomain, os.Getenv("OKTA_TOKEN"))
	lambda.StartHandler(internal.Lambdaify(api.ServeUserApplications(service)))
}
