package traefik_api_key_redis_middleware

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gomodule/redigo/redis"
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
	redisPool   *redis.Pool
	cache       map[string]string
	cacheMutex  sync.RWMutex
	bearerRegex *regexp.Regexp
}

func createRedisPool(redisURL string) *redis.Pool {
	return &redis.Pool{
		MaxIdle:     5,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			return redis.DialURL(redisURL)
		},
	}
}

func lookupKey(conn redis.Conn, key string) (string, error) {
	val, err := redis.String(conn.Do("GET", key))
	if err == redis.ErrNil {
		return "", err
	} else if err != nil {
		return "", err
	}
	return val, nil
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.RedisHost == nil {
	}
	pool := createRedisPool(*config.RedisHost)

	return &ApiKeyRedis{
		next:        next,
		redisPool:   pool,
		cache:       make(map[string]string),
		bearerRegex: regexp.MustCompile(`^Bearer\s+(.+)$`),
	}, nil
}

func (a *ApiKeyRedis) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	conn := a.redisPool.Get()
	defer conn.Close()

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

	val, err := lookupKey(conn, apiToken)
	if err == redis.ErrNil {
		http.Error(rw, "API key is not valid", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(rw, "Error when retrieving API key", http.StatusInternalServerError)
		return
	}

	a.cacheMutex.Lock()
	a.cache[apiToken] = val
	a.cacheMutex.Unlock()

	a.next.ServeHTTP(rw, req)
}
