package traefik_api_key_redis_middleware

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

type Config struct {
	RedisHost *string `yaml:"redisHost"`
}

type Response struct {
	Message    string `json:"message"`
	StatusCode int    `json:"statusCode"`
}

func CreateConfig() *Config {
	return &Config{}
}

type ApiKeyRedis struct {
	next        http.Handler
	redisHost   string
	cache       map[string]string
	cacheMutex  sync.RWMutex
	bearerRegex *regexp.Regexp
}

func getKeyFromRedis(inst string, key string) (string, error) {
	// create connection
	conn, err := net.Dial("tcp", inst)
	if err != nil {
		return "nil", fmt.Errorf("failed to connect to Redis: %v", err)
	}
	defer conn.Close()

	// send command to Redis
	cmd := fmt.Sprintf("*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n", len(key), key)
	_, err = conn.Write([]byte(cmd))
	if err != nil {
		return "", fmt.Errorf("failed to write to Redis: %v", err)
	}

	// read response
	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read from Redis: %v", err)
	}

	// check if key not found
	if resp == "$-1\r\n" {
		return "", fmt.Errorf("key not found")
	}

	// check for value
	if resp[0] == '$' {
		value, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read from Redis: %v", err)
		}
		return value[:len(value)-2], nil
	}

	return "", fmt.Errorf("failed to get value from Redis %s", resp)
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.RedisHost == nil {
	}
	redisHost := "kraken-api-redis.kraken-api.svc.data-applications:6379"

	return &ApiKeyRedis{
		next:        next,
		redisHost:   redisHost,
		cache:       make(map[string]string),
		bearerRegex: regexp.MustCompile(`^Bearer\s+(.+)$`),
	}, nil
}

func (a *ApiKeyRedis) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var bearerToken string

	apiHeader := req.Header.Get("X-API-KEY")
	authHeader := req.Header.Get("Authorization")

	if apiHeader == "" && authHeader == "" {
		http.Error(rw, "API key is not valid", http.StatusUnauthorized)
		return
	}

	if apiHeader != "" {
		if _, exists := a.cache[apiHeader]; exists {
			// a.next.ServeHTTP(rw, req)
			response := Response{Message: "x-api-key is in cache", StatusCode: http.StatusOK}
			rw.Header().Set("Content-Type", "application/json; charset=utf-8")
			rw.WriteHeader(response.StatusCode)
			json.NewEncoder(rw).Encode(response)
			return
		}
	}

	if authHeader != "" {
		bearerMatches := a.bearerRegex.FindStringSubmatch(strings.TrimSpace(authHeader))
		if len(bearerMatches) == 2 {
			bearerToken = bearerMatches[1]
			if _, exists := a.cache[bearerToken]; exists {
				// a.next.ServeHTTP(rw, req)
				response := Response{Message: "bearer token is in cache", StatusCode: http.StatusOK}
				rw.Header().Set("Content-Type", "application/json; charset=utf-8")
				rw.WriteHeader(response.StatusCode)
				json.NewEncoder(rw).Encode(response)
				return
			}
		} else {
			http.Error(rw, "Bearer token is not valid", http.StatusUnauthorized)
			return
		}
	}

	apiToken := apiHeader
	if apiToken == "" {
		apiToken = bearerToken
	}

	val, err := getKeyFromRedis(a.redisHost, apiToken)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error getting key: %v", err), http.StatusUnauthorized)
	}

	a.cacheMutex.Lock()
	a.cache[apiToken] = val
	a.cacheMutex.Unlock()

	// a.next.ServeHTTP(rw, req)
	response := Response{Message: "Got key from redis and saved to cache", StatusCode: http.StatusOK}
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(response.StatusCode)
	json.NewEncoder(rw).Encode(response)
}
