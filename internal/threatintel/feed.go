package threatintel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Entry is a single blocked IP or CIDR with its source feed URL.
type Entry struct {
	CIDR   string
	Source string
}

// Fetcher downloads and parses threat intel feeds.
type Fetcher struct {
	client *http.Client
}

func NewFetcher() *Fetcher {
	return &Fetcher{client: &http.Client{Timeout: 30 * time.Second}}
}

// FetchAll fetches all feeds concurrently and returns a deduplicated list of entries.
func (f *Fetcher) FetchAll(ctx context.Context, urls []string) ([]Entry, error) {
	type result struct {
		entries []Entry
		err     error
	}

	results := make([]result, len(urls))
	var wg sync.WaitGroup

	for i, url := range urls {
		wg.Add(1)
		go func(idx int, feedURL string) {
			defer wg.Done()
			entries, err := f.fetchOne(ctx, feedURL)
			results[idx] = result{entries: entries, err: err}
		}(i, url)
	}

	wg.Wait()

	seen := make(map[string]struct{})
	var all []Entry
	for i, r := range results {
		if r.err != nil {
			slog.Warn("feed fetch failed", "url", urls[i], "err", r.err)
			continue
		}
		for _, e := range r.entries {
			if _, ok := seen[e.CIDR]; !ok {
				seen[e.CIDR] = struct{}{}
				all = append(all, e)
			}
		}
	}

	slog.Info("threat intel feeds fetched", "total_entries", len(all))
	return all, nil
}

func (f *Fetcher) fetchOne(ctx context.Context, feedURL string) ([]Entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, feedURL)
	}

	return parseFeed(resp.Body, feedURL)
}

// parseFeed parses line-delimited IP/CIDR feeds.
// Lines starting with '#' or ';' are treated as comments.
// Entries may be bare IPs or CIDR notation; bare IPs get /32 appended.
func parseFeed(r io.Reader, source string) ([]Entry, error) {
	var entries []Entry
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		// Some feeds have trailing fields separated by spaces/semicolons
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ';' || r == ','
		})
		if len(fields) == 0 {
			continue
		}
		raw := fields[0]

		// Validate: accept CIDR or plain IP
		if strings.Contains(raw, "/") {
			_, _, err := net.ParseCIDR(raw)
			if err != nil {
				continue
			}
			entries = append(entries, Entry{CIDR: raw, Source: source})
		} else {
			ip := net.ParseIP(raw)
			if ip == nil {
				continue
			}
			cidr := raw + "/32"
			if ip.To4() == nil {
				cidr = raw + "/128"
			}
			entries = append(entries, Entry{CIDR: cidr, Source: source})
		}
	}
	return entries, scanner.Err()
}
