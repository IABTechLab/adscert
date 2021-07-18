package utils

import (
	"os"
	"strconv"
)

func GetEnvVarString(key string, defaultValue string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return defaultValue
}

func GetEnvVarInt(key string, defaultValue int) int {
	if v, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(v); err != nil {
			return i
		}
	}
	return defaultValue
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
