package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
	"golang.org/x/net/publicsuffix"
)

type urlChecker struct {
	timeout             time.Duration
	documentRoot        string
	excludedPattern     *regexp.Regexp
	excludePrivateHosts bool
	excludeLocalhost    bool
	excludeLinkLocal    bool
	stripRelativePrefix bool
	semaphore           semaphore
}

func newURLChecker(t time.Duration, d string, r *regexp.Regexp, excludePrivateHosts, excludeLocalhost, excludeLinkLocal, stripRelativePrefix bool, s semaphore) urlChecker {
	return urlChecker{t, d, r, excludePrivateHosts, excludeLocalhost, excludeLinkLocal, stripRelativePrefix, s}
}

func (c urlChecker) Check(u string, f string) error {
	u, local, err := c.resolveURL(u, f)
	if err != nil {
		return err
	}

	if !local {
		uu, _ := url.Parse(u)
		host := uu.Hostname()
		if ip := net.ParseIP(host); ip != nil {
			if c.excludePrivateHosts && isPrivate(ip) {
				return nil
			}
			if c.excludeLocalhost && ip.IsLoopback() {
				return nil
			}
			if c.excludeLinkLocal && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
				return nil
			}
		} else {
			if host == "localhost" {
				if c.excludeLocalhost {
					return nil
				}
			} else if _, icann := publicsuffix.PublicSuffix(host); !icann && c.excludePrivateHosts {
				return nil // private domain
			}
		}
	}

	if c.excludedPattern != nil && c.excludedPattern.MatchString(u) {
		return nil
	}

	if local {
		_, err := os.Stat(u)
		// A link's extension need not match its on-disk source: Hugo pretty
		// URLs point at a directory-style path (e.g. `foo/`) and rendered
		// `.html` links map back to a `foo.md` source file. If the raw path is
		// missing, retry against the Markdown source before giving up.
		if err != nil {
			var md string
			switch ext := path.Ext(u); ext {
			case "":
				md = u + ".md"
			case ".html", ".htm":
				md = strings.TrimSuffix(u, ext) + ".md"
			}
			if md != "" {
				if _, mdErr := os.Stat(md); mdErr == nil {
					return nil
				}
			}
		}
		return err
	}

	c.semaphore.Request()
	defer c.semaphore.Release()

	sc, err := c.get(u)
	if sc >= http.StatusBadRequest {
		return fmt.Errorf("%s (HTTP error %d)", http.StatusText(sc), sc)
	}
	// Ignore errors from fasthttp about small buffer for URL headers,
	// the content is discarded anyway.
	if _, ok := err.(*fasthttp.ErrSmallBuffer); ok {
		err = nil
	}
	return err
}

// userAgent is sent on every outbound request. Many hosts reject requests
// with no User-Agent (HTTP 403) or bounce them through a redirect loop; a
// browser-like value avoids those false positives.
const userAgent = "Mozilla/5.0 (compatible; liche link checker; +https://github.com/appscodelabs/liche)"

// get performs a GET for u with a browser-like User-Agent, following redirects
// manually so the header is preserved across every hop.
func (c urlChecker) get(u string) (int, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetUserAgent(userAgent)

	for redirects := 0; ; redirects++ {
		if redirects > defaultMaxRedirects {
			return resp.StatusCode(), fmt.Errorf("too many redirects detected when doing the request")
		}
		req.SetRequestURI(u)

		var err error
		if c.timeout == 0 {
			err = fasthttp.Do(req, resp)
		} else {
			err = fasthttp.DoTimeout(req, resp, c.timeout)
		}
		if err != nil {
			return resp.StatusCode(), err
		}

		sc := resp.StatusCode()
		if sc < http.StatusMultipleChoices || sc >= http.StatusBadRequest {
			return sc, nil
		}
		loc := resp.Header.Peek("Location")
		if len(loc) == 0 {
			return sc, nil
		}
		next, err := resolveLocation(u, string(loc))
		if err != nil {
			return sc, err
		}
		u = next
	}
}

const defaultMaxRedirects = 16

// resolveLocation resolves a possibly-relative redirect target against the
// URL that produced it.
func resolveLocation(base, loc string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	l, err := url.Parse(loc)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(l).String(), nil
}

func (c urlChecker) CheckMany(us []string, f string, rc chan<- urlResult) {
	wg := sync.WaitGroup{}

	for _, s := range us {
		wg.Add(1)

		go func(s string) {
			rc <- urlResult{s, c.Check(s, f)}
			wg.Done()
		}(s)
	}

	wg.Wait()
	close(rc)
}

func (c urlChecker) resolveURL(u string, f string) (string, bool, error) {
	uu, err := url.Parse(u)
	if err != nil {
		return "", false, err
	}

	if uu.Scheme != "" {
		return u, false, nil
	}

	if !path.IsAbs(uu.Path) {
		p := uu.Path
		if c.stripRelativePrefix {
			p = strings.TrimPrefix(p, "../")
		}
		return path.Join(filepath.Dir(f), p), true, nil
	}

	if c.documentRoot == "" {
		return "", false, fmt.Errorf("document root directory is not specified")
	}

	ru, err := url.Parse(c.documentRoot)
	if err != nil {
		return "", false, err
	}
	if ru.Scheme != "" {
		ru.Path = path.Join(ru.Path, uu.Path)
		return ru.String(), false, nil
	}

	return path.Join(c.documentRoot, uu.Path), true, nil
}

// isPrivate reports whether `ip' is a local address, according to
// RFC 1918 (IPv4 addresses) and RFC 4193 (IPv6 addresses).
// xref: https://go-review.googlesource.com/c/go/+/162998/
// xref: https://github.com/golang/go/issues/29146
func isPrivate(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// Local IPv4 addresses are defined in https://tools.ietf.org/html/rfc1918
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	// Local IPv6 addresses are defined in https://tools.ietf.org/html/rfc4193
	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc
}
