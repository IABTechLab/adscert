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

func MergeUniques(list []string) []string {
	uniques := map[string]struct{}{}
	for _, v := range list {
		uniques[v] = struct{}{}
	}

	list = make([]string, 0)
	for k := range uniques {
		list = append(list, k)
	}

	return list
}
