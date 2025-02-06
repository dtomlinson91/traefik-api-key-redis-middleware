package traefik_api_key_redis_middleware

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/redis/go-redis/v9"
)

type Config struct {
	RedisHost *string `yaml:"redisHost"`
	RedisUser *string `yaml:"redisUser"`
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
	redisClient *redis.Client
	cache       map[string]string
	cacheMutex  sync.RWMutex
	bearerRegex *regexp.Regexp
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.RedisHost == nil {
		return nil, fmt.Errorf("RedisHost is required")
	}

	options := &redis.Options{
		Addr: *config.RedisHost,
	}
	// if config.RedisUser != nil {
	// 	options.Username = *config.RedisUser
	// }

	redisClient := redis.NewClient(options)

	return &ApiKeyRedis{
		next:        next,
		redisClient: redisClient,
		cache:       make(map[string]string),
		bearerRegex: regexp.MustCompile(`^Bearer\s+(.+)$`),
	}, nil
}

func (a *ApiKeyRedis) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	var bearerToken string

	apiHeader := req.Header.Get("X-API-KEY")
	authHeader := req.Header.Get("Authorization")

	if apiHeader == "" && authHeader == "" {
		http.Error(rw, "API key is not valid", http.StatusUnauthorized)
		return
	}

	if apiHeader != "" {
		if _, exists := a.cache[apiHeader]; exists {
			a.next.ServeHTTP(rw, req)
			return
		}
	}

	if authHeader != "" {
		bearerMatches := a.bearerRegex.FindStringSubmatch(strings.TrimSpace(authHeader))
		if len(bearerMatches) == 2 {
			bearerToken = bearerMatches[1]
			if _, exists := a.cache[bearerToken]; exists {
				a.next.ServeHTTP(rw, req)
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
	val, err := a.redisClient.Get(ctx, apiToken).Result()
	if err != nil {
		http.Error(rw, "API key is not valid", http.StatusUnauthorized)
		return
	}

	a.cacheMutex.Lock()
	a.cache[apiToken] = val
	a.cacheMutex.Unlock()

	a.next.ServeHTTP(rw, req)
}
