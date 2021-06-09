package utils

import (
	"net/url"

	"github.com/IABTechLab/adscert/internal/logger"
	"golang.org/x/net/publicsuffix"
)

func ParseURLComponents(destinationURL string) (*url.URL, string, error) {
	parsedDestURL, err := url.Parse(destinationURL)
	if err != nil {
		logger.Logger.Error("Error parsing destination url component: ", err)
		return nil, "", err
	}
	tldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(parsedDestURL.Hostname())
	if err != nil {
		logger.Logger.Error("Error retreiving tld: ", err)
		return nil, "", err
	}
	return parsedDestURL, tldPlusOne, nil
}
