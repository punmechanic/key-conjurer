package main

import (
	"strings"

	"github.com/RobotsAndPencils/go-saml"
)

type RoleProviderPair struct {
	RoleARN     string
	ProviderARN string
}

func ListSAMLRoles(response *saml.Response) []string {
	if response == nil {
		return nil
	}

	roleURL := "https://aws.amazon.com/SAML/Attributes/Role"
	var names []string
	for _, v := range response.GetAttributeValues(roleURL) {
		p := getARN(v)
		idx := strings.Index(p.RoleARN, "role/")
		parts := strings.Split(p.RoleARN[idx:], "/")
		names = append(names, parts[1])
	}

	return names
}

func FindRoleInSAML(roleName string, response *saml.Response) (RoleProviderPair, bool) {
	var rpp RoleProviderPair
	if response == nil {
		return rpp, false
	}

	roleURL := "https://aws.amazon.com/SAML/Attributes/Role"
	roleSubstr := "role/"
	attrs := response.GetAttributeValues(roleURL)
	if len(attrs) == 0 {
		return rpp, false
	}

	var pairs []RoleProviderPair
	for _, v := range response.GetAttributeValues(roleURL) {
		pairs = append(pairs, getARN(v))
	}

	if len(pairs) == 0 {
		return rpp, false
	}

	var pair RoleProviderPair
	for _, p := range pairs {
		idx := strings.Index(p.RoleARN, roleSubstr)
		parts := strings.Split(p.RoleARN[idx:], "/")
		if strings.EqualFold(parts[1], roleName) {
			pair = p
		}
	}

	if pair.RoleARN == "" {
		return rpp, false
	}

	return pair, true
}

func getARN(value string) RoleProviderPair {
	p := RoleProviderPair{}
	roles := strings.Split(value, ",")
	if len(roles) >= 2 {
		if strings.Contains(roles[0], "saml-provider/") {
			p.ProviderARN = roles[0]
			p.RoleARN = roles[1]
		} else {
			p.ProviderARN = roles[1]
			p.RoleARN = roles[0]
		}
	}
	return p
}

func ParseBase64EncodedSAMLResponse(xml string) (*saml.Response, error) {
	return saml.ParseEncodedResponse(xml)
}
