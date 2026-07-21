package flowstate

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore is a Store backed by Redis, used to hold the upstream id_token
// between login and logout when REDIS_DSN is configured.
type RedisStore struct {
	client *redis.Client
	prefix string
}

// NewRedisStore parses a redis:// DSN and returns a Store. The prefix is
// prepended to every key.
func NewRedisStore(dsn, prefix string) (*RedisStore, error) {
	opt, err := redis.ParseURL(dsn)
	if err != nil {
		return nil, err
	}
	return &RedisStore{client: redis.NewClient(opt), prefix: prefix}, nil
}

func (s *RedisStore) key(k string) string { return s.prefix + k }

func (s *RedisStore) Put(ctx context.Context, key, value string, ttl time.Duration) error {
	return s.client.Set(ctx, s.key(key), value, ttl).Err()
}

func (s *RedisStore) Get(ctx context.Context, key string) (string, error) {
	v, err := s.client.Get(ctx, s.key(key)).Result()
	if err == redis.Nil {
		return "", nil
	}
	return v, err
}

func (s *RedisStore) Del(ctx context.Context, key string) error {
	return s.client.Del(ctx, s.key(key)).Err()
}
