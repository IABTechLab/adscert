package utils

import (
	"net/url"
	"os"

	"golang.org/x/net/publicsuffix"
)

func ParseURLComponents(destinationURL string) (*url.URL, string, error) {
	parsedDestURL, err := url.Parse(destinationURL)
	if err != nil {
		return nil, "", err
	}
	tldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(parsedDestURL.Hostname())
	if err != nil {
		return nil, "", err
	}
	return parsedDestURL, tldPlusOne, nil
}

func GetEnvVar(key string) string {
	v, ok := os.LookupEnv(key)
	if ok {
		return v
	}
	return ""
}
