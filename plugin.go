package traefik_api_key_redis_middleware

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/mediocregopher/radix/v4"
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
	redisPool   radix.Client
	cache       map[string]string
	cacheMutex  sync.RWMutex
	bearerRegex *regexp.Regexp
}

func createRedisPool(ctx context.Context, redisURL string) radix.Client {
	client, err := radix.PoolConfig{}.New(ctx, "tcp", redisURL)
	if err != nil {
		panic(err)
	}
	return client
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.RedisHost == nil {
	}
	redisHost := "kraken-api-redis.kraken-api.svc.data-applications:6379"
	pool := createRedisPool(ctx, redisHost)

	return &ApiKeyRedis{
		next:        next,
		redisPool:   pool,
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

	var rkey string
	if err := a.redisPool.Do(ctx, radix.Cmd(&rkey, "GET", apiToken)); err != nil {
		http.Error(rw, "API key is not valid", http.StatusUnauthorized)
		return
	}

	a.cacheMutex.Lock()
	a.cache[apiToken] = rkey
	a.cacheMutex.Unlock()

	a.next.ServeHTTP(rw, req)
}
