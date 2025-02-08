package traefik_api_key_redis_middleware

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"log"
)

var ErrKeyNotFound = errors.New("key not found")

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
	redisHost   *string
	cache       map[string][]byte
	cacheMutex  sync.RWMutex
	bearerRegex *regexp.Regexp
}

type KeyData struct {
	Email       string `json:"email"`
	Owner       string `json:"owner"`
	Team        string `json:"team"`
	Sub_team    string `json:"sub_team"`
	Personal    bool   `json:"personal"`
	Environment string `json:"environment"`
}

func getKeyFromRedis(inst string, key string) (string, error) {
	// create connection
	conn, err := net.Dial("tcp", inst)
	if err != nil {
		return "", fmt.Errorf("failed to connect to Redis: %v", err)
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
		return "", ErrKeyNotFound
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

func getHashFromRedis(inst string, key string) (*KeyData, error) {
	r := &KeyData{}

	// create connection
	conn, err := net.Dial("tcp", inst)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %v", err)
	}
	defer conn.Close()

	// send command to Redis
	cmd := fmt.Sprintf("*2\r\n$7\r\nHGETALL\r\n$%d\r\n%s\r\n", len(key), key)
	_, err = conn.Write([]byte(cmd))
	if err != nil {
		return nil, fmt.Errorf("failed to write to Redis: %v", err)
	}

	// read response
	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read from Redis: %v", err)
	}

	if resp[0] != '*' {
		return nil, fmt.Errorf("failed to get hash from Redis %s", resp)
	}

	count, err := strconv.Atoi(strings.TrimSpace(resp[1:]))
	if err != nil {
		return nil, fmt.Errorf("failed to convert count to int: %v", err)
	}

	if count == 0 {
		return nil, ErrKeyNotFound
	}

	// get key:value pairs
	for i := 0; i < count; i += 2 {
		if _, err := reader.ReadString('\n'); err != nil {
			return nil, fmt.Errorf("failed to read field length: %v", err)
		}

		field, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read field: %v", err)
		}
		field = strings.TrimSpace(field)

		if _, err := reader.ReadString('\n'); err != nil {
			return nil, fmt.Errorf("failed to read value length: %v", err)
		}

		value, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read value: %v", err)
		}
		value = strings.TrimSpace(value)

		switch strings.ToLower(field) {
		case "email":
			r.Email = value
		case "owner":
			r.Owner = value
		case "team":
			r.Team = value
		case "sub_team":
			r.Sub_team = value
		case "personal":
			r.Personal = strings.ToLower(value) == "true"
		case "environment":
			r.Environment = value
		}

	}
	return r, nil
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.RedisHost == nil {
		return nil, fmt.Errorf("redis host is required")
	}

	return &ApiKeyRedis{
		next:        next,
		redisHost:   config.RedisHost,
		cache:       make(map[string][]byte),
		bearerRegex: regexp.MustCompile(`^Bearer\s+(.+)$`),
	}, nil
}

func (a *ApiKeyRedis) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var bearerToken string

	apiHeader := req.Header.Get("X-API-KEY")
	authHeader := req.Header.Get("Authorization")

	if apiHeader == "" && authHeader == "" {
		http.Error(rw, "No authentication header provided", http.StatusUnauthorized)
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
			http.Error(rw, "Invalid Bearer token", http.StatusUnauthorized)
			return
		}
	}

	apiToken := apiHeader
	if apiToken == "" {
		apiToken = bearerToken
	}

	// val, err := getKeyFromRedis(*a.redisHost, apiToken)
	val, err := getHashFromRedis(*a.redisHost, apiToken)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			http.Error(rw, "Invalid API key", http.StatusUnauthorized)
			return
		}
		log.Printf("Error getting key from Redis: %v", err)
		http.Error(rw, "Server error when trying to authenticate", http.StatusInternalServerError)
		return
	}

	jval, err := json.Marshal(val)
	if err != nil {
		log.Printf("Error marshalling value: %v", err)
		http.Error(rw, "Server error when trying to authenticate", http.StatusInternalServerError)
	}
	a.cacheMutex.Lock()
	a.cache[apiToken] = jval
	a.cacheMutex.Unlock()

	a.next.ServeHTTP(rw, req)
}
