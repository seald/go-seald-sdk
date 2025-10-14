package api_helper

import (
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type blockingTransport struct {
	startCh   chan struct{}
	releaseCh chan struct{}
	doneCh    chan struct{}

	mu      sync.Mutex
	current int
	maxSeen int
}

func newBlockingTransport(buffer int) *blockingTransport {
	return &blockingTransport{
		startCh:   make(chan struct{}, buffer),
		releaseCh: make(chan struct{}),
		doneCh:    make(chan struct{}, buffer),
	}
}

func (t *blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.current++
	if t.current > t.maxSeen {
		t.maxSeen = t.current
	}
	t.mu.Unlock()

	t.startCh <- struct{}{}
	<-t.releaseCh

	t.mu.Lock()
	t.current--
	t.mu.Unlock()

	t.doneCh <- struct{}{}

	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("{}")),
		Request:    req,
	}, nil
}

func (t *blockingTransport) MaxSeen() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.maxSeen
}

func waitForEvent(t *testing.T, ch <-chan struct{}, event string) {
	t.Helper()
	select {
	case <-ch:
		return
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", event)
	}
}

func TestApiClientParallelRequests(t *testing.T) {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.StampMilli}).With().Timestamp().Str("instance", "testApiHelper").Logger()
	const requests = 5
	transport := newBlockingTransport(requests)

	t.Run("respects max parallel requests limit", func(t *testing.T) {
		const limit = 2

		client := NewApiClient("http://example.com", nil, logger, limit)
		client.client = &http.Client{Transport: transport}

		var wg sync.WaitGroup
		wg.Add(requests)
		for i := 0; i < requests; i++ {
			go func() {
				defer wg.Done()
				_, err := client.MakeRequest("GET", "/test", nil, nil, http.StatusOK)
				require.NoError(t, err)
			}()
		}

		for i := 0; i < requests; i++ {
			waitForEvent(t, transport.startCh, "request start")
			transport.releaseCh <- struct{}{}
			waitForEvent(t, transport.doneCh, "request completion")
		}

		wg.Wait()

		assert.LessOrEqual(t, transport.MaxSeen(), limit)
	})

	t.Run("allows unlimited parallel requests", func(t *testing.T) {
		client := NewApiClient("http://example.com", nil, logger, -1) // -1 means no limit
		client.client = &http.Client{Transport: transport}

		var wg sync.WaitGroup
		wg.Add(requests)
		for i := 0; i < requests; i++ {
			go func() {
				defer wg.Done()
				_, err := client.MakeRequest("GET", "/test", nil, nil, http.StatusOK)
				require.NoError(t, err)
			}()
		}

		// Wait for all requests to start
		for i := 0; i < requests; i++ {
			waitForEvent(t, transport.startCh, "request start")
		}

		// All requests should be in flight at this point
		assert.Equal(t, requests, transport.MaxSeen())

		// Release all requests
		for i := 0; i < requests; i++ {
			transport.releaseCh <- struct{}{}
			waitForEvent(t, transport.doneCh, "request completion")
		}

		wg.Wait()
	})
}
