package main

import (
	"github.com/IABTechLab/adscert"
	"github.com/davecgh/go-spew/spew"
)

func main() {
	domains := []string{"_delivery._adscert.ssai-serving.tk", "_delivery._adscert.exchange-holding-company.ga"}
	adsCertVerifier := adscert.NewAdsCertVerifier(domains)
	spew.Dump(adsCertVerifier)
}
