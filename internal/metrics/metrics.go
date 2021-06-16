package metrics

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// Labels
const (
	signErrorLabel string = "error"

	verifyErrorLabel string = "error"

	verifyResultTypeLabel  string = "type"
	verifyResultValidLabel string = "valid"
)

// Signing Errors
type SignErrorCode string

const (
	SignErrorNone          SignErrorCode = "no_error"
	SignErrorParseUrl      SignErrorCode = "parsing_url_error"
	SignErrorGenerateNonce SignErrorCode = "generate_nonce_error"
	SignErrorEmboss        SignErrorCode = "emboss_error"
)

// Verification Errors
type VerifyErrorCode string

const (
	VerifyErrorNone               VerifyErrorCode = "no_error"
	VerifyErrorParseUrl           VerifyErrorCode = "url_parse"
	VerifyErrorSignatureDecode    VerifyErrorCode = "signature_decode"
	VerifyErrorUnrelatedSignature VerifyErrorCode = "unrelated_signature"
	VerifyErrorNoSharedSecret     VerifyErrorCode = "no_shared_secret"
	VerifyErrorCounterPartyLookUp VerifyErrorCode = "counter_party_lookup"
)

// Verification Result Type
type verifyResultType string

const (
	VerifyResultTypeBody verifyResultType = "body"
	VerifyResultTypeUrl  verifyResultType = "url"
)

// adscertMetricsRegistry Prometheus registry capturing ads.cert related metrics
var adscertMetricsRegistry *prometheus.Registry

// Creates all metrics
var (
	SignCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "adscert_sign_count",
		Help: "The total number of requests signed",
	}, []string{signErrorLabel})
	VerifyCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "adscert_verify_count",
		Help: "The total number of requests verified",
	}, []string{verifyErrorLabel})
	VerifyResultCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "adscert_verify_result_count",
		Help: "The total number of valid signed requests",
	}, []string{verifyResultTypeLabel, verifyResultValidLabel})
)

func init() {
	adscertMetricsRegistry = prometheus.NewRegistry()
	adscertMetricsRegistry.Register(SignCounter)
	adscertMetricsRegistry.Register(VerifyCounter)
	adscertMetricsRegistry.Register(VerifyResultCounter)
}

func GetAdscertMetricsRegistry() *prometheus.Registry {
	return adscertMetricsRegistry
}

func RecordSigningMetrics(err SignErrorCode) {
	SignCounter.With(prometheus.Labels{
		signErrorLabel: string(err),
	}).Inc()
}

func RecordVerifyMetrics(err VerifyErrorCode) {
	VerifyCounter.With(prometheus.Labels{
		verifyErrorLabel: string(err),
	}).Inc()
}

func RecordVerifyResultMetrics(t verifyResultType, valid bool) {
	VerifyResultCounter.With(prometheus.Labels{
		verifyResultTypeLabel:  string(t),
		verifyResultValidLabel: strconv.FormatBool(valid),
	}).Inc()
}
