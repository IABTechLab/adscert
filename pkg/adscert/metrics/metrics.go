package metrics

import (
	"strconv"
	"time"

	"github.com/IABTechLab/adscert/internal/adscerterrors"
	"github.com/prometheus/client_golang/prometheus"
)

const namespace string = "adscert"

var standardMillisecondBuckets []float64 = []float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000}
var standardMicrosecondBuckets []float64 = []float64{10, 25, 50, 100, 250, 500, 1000, 2000, 5000, 10000}

// Labels
const (
	dnsLookupErrorLabel string = "error"

	signErrorLabel string = "error"

	verifyErrorLabel string = "error"

	verifyOutcomeTypeLabel  string = "type"
	verifyOutcomeValidLabel string = "valid"
)

// Verification Outcome Type
type verifyOutcomeType string

const (
	VerifyOutcomeTypeBody verifyOutcomeType = "body"
	VerifyOutcomeTypeUrl  verifyOutcomeType = "url"
)

// adscertMetricsRegistry Prometheus registry capturing ads.cert related metrics
var adscertMetricsRegistry *prometheus.Registry

// Creates all metrics
var (
	DNSLookupCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "dns_lookup_count",
		Help:      "The total number of requests verified",
	}, []string{dnsLookupErrorLabel})
	DNSLookupTimeHistogram = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "dns_lookup_ms",
		Help:      "Milliseconds to lookup DNS.",
		Buckets:   standardMillisecondBuckets,
	})
	SignCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "sign_count",
		Help:      "The total number of requests signed.",
	}, []string{signErrorLabel})
	SignTimeHistogram = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "sign_time_us",
		Help:      "Microseconds to sign a request.",
		Buckets:   standardMicrosecondBuckets,
	})
	VerifyCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "verify_count",
		Help:      "The total number of requests verified.",
	}, []string{verifyErrorLabel})
	VerifyOutcomeCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "verify_outcome_count",
		Help:      "The total number of valid signed requests.",
	}, []string{verifyOutcomeTypeLabel, verifyOutcomeValidLabel})
	VerifyTimeHistogram = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "verify_time_us",
		Help:      "Microseconds to verify a request.",
		Buckets:   standardMicrosecondBuckets,
	})
)

// All metric collectors
var collectors []prometheus.Collector = []prometheus.Collector{
	DNSLookupCounter,
	DNSLookupTimeHistogram,
	SignCounter,
	SignTimeHistogram,
	VerifyCounter,
	VerifyOutcomeCounter,
	VerifyTimeHistogram,
}

func init() {
	adscertMetricsRegistry = prometheus.NewRegistry()
	for _, collector := range collectors {
		adscertMetricsRegistry.MustRegister(collector)
	}
}

func GetAdscertMetricsRegistry() *prometheus.Registry {
	return adscertMetricsRegistry
}

func RecordDNSLookup(err adscerterrors.DNSLookupErrorCode) {
	var DNSLookupErr string

	if err != nil {
		DNSLookupErr = err.Code
	}

	DNSLookupCounter.With(prometheus.Labels{
		dnsLookupErrorLabel: DNSLookupErr,
	}).Inc()
}

func RecordDNSLookupTime(observeTime time.Duration) {
	DNSLookupTimeHistogram.Observe(float64(observeTime.Milliseconds()))
}

func RecordSigning(err adscerterrors.SigningErrorCode) {
	var signError string

	if err != nil {
		signError = err.Code
	}

	SignCounter.With(prometheus.Labels{
		signErrorLabel: signError,
	}).Inc()
}

func RecordSigningTime(observeTime time.Duration) {
	SignTimeHistogram.Observe(float64(observeTime.Microseconds()))
}

func RecordVerify(err adscerterrors.VerifyErrorCode) {
	var verifyError string

	if err != nil {
		verifyError = err.Code
	}

	VerifyCounter.With(prometheus.Labels{
		verifyErrorLabel: verifyError,
	}).Inc()
}

func RecordVerifyOutcome(t verifyOutcomeType, valid bool) {
	VerifyOutcomeCounter.With(prometheus.Labels{
		verifyOutcomeTypeLabel:  string(t),
		verifyOutcomeValidLabel: strconv.FormatBool(valid),
	}).Inc()
}

func RecordVerifyTime(observeTime time.Duration) {
	VerifyTimeHistogram.Observe(float64(observeTime.Microseconds()))
}
