package utils

import (
	"os"
)

func GetEnvVar(key string) string {
	v, ok := os.LookupEnv(key)
	if ok {
		return v
	}
	return ""
}
