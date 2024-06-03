package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dchest/safefile"

	"github.com/jedisct1/dlog"
	"github.com/jedisct1/go-dnsstamps"
	"github.com/jedisct1/go-minisign"
)

type SourceFormat int

const (
	SourceFormatV2 = iota
)

const MinimumPrefetchInterval time.Duration = 10 * time.Minute

type Source struct {
	name        string
	urls        []*url.URL
	format      SourceFormat
	bin         []byte
	minisignKey *minisign.PublicKey
	cacheFile   string
	cacheTTL    time.Duration
	refresh     time.Time
	prefix      string
}

// timeNow() is replaced by tests to provide a static value
var timeNow = time.Now

func (source *Source) checkSignature(bin, sig []byte) error {
	signature, err := minisign.DecodeSignature(string(sig))
	if err == nil {
		_, err = source.minisignKey.Verify(bin, signature)
	}
	return err
}

func (source *Source) fetchFromCache(now time.Time) (time.Duration, error) {
	var err error
	var bin, sig []byte
	if bin, err = os.ReadFile(source.cacheFile); err != nil {
		return 0, err
	}
	if sig, err = os.ReadFile(source.cacheFile + ".minisig"); err != nil {
		return 0, err
	}
	if err = source.checkSignature(bin, sig); err != nil {
		return 0, err
	}
	source.bin = bin
	var fi os.FileInfo
	if fi, err = os.Stat(source.cacheFile); err != nil {
		return 0, err
	}
	var ttl time.Duration = 0
	if elapsed := now.Sub(fi.ModTime()); elapsed < source.cacheTTL {
		ttl = source.cacheTTL - elapsed
		dlog.Debugf("Source [%s] cache file [%s] is still fresh, next update in %v", source.name, source.cacheFile, ttl)
	} else {
		dlog.Noticef("Source [%s] cache file [%s] needs to be refreshed", source.name, source.cacheFile)
	}
	return ttl, nil
}

func writeSource(f string, bin, sig []byte) error {
	var err error
	var fSrc, fSig *safefile.File
	if fSrc, err = safefile.Create(f, 0o644); err != nil {
		return err
	}
	defer fSrc.Close()
	if fSig, err = safefile.Create(f+".minisig", 0o644); err != nil {
		return err
	}
	defer fSig.Close()
	if _, err = fSrc.Write(bin); err != nil {
		return err
	}
	if _, err = fSig.Write(sig); err != nil {
		return err
	}
	if err = fSrc.Commit(); err != nil {
		return err
	}
	return fSig.Commit()
}

func (source *Source) updateCache(bin, sig []byte, now time.Time) {
	file := source.cacheFile
	absPath := file
	if resolved, err := filepath.Abs(file); err != nil {
		absPath = resolved
	}

	if !bytes.Equal(source.bin, bin) {
		if err := writeSource(file, bin, sig); err != nil {
			dlog.Warnf("Couldn't write cache file [%s]: %s", absPath, err) // an error writing to the cache isn't fatal
		}
	}
	if err := os.Chtimes(file, now, now); err != nil {
		dlog.Warnf("Couldn't update cache file [%s]: %s", absPath, err)
	}
	_ = os.Chtimes(file+".minisig", now, now)

	source.bin = bin
}

func (source *Source) parseURLs(urls []string) {
	for _, urlStr := range urls {
		if srcURL, err := url.Parse(urlStr); err != nil {
			dlog.Warnf("Source [%s] failed to parse URL [%s]", source.name, urlStr)
		} else {
			source.urls = append(source.urls, srcURL)
		}
	}
}

func fetchFromURL(xTransport *XTransport, u *url.URL) ([]byte, error) {
	bin, _, _, _, err := xTransport.GetWithCompression(u, "", DefaultTimeout)
	return bin, err
}

func (source *Source) fetchNew(xTransport *XTransport, now time.Time) (time.Duration, error) {
	var err error
	ttl := MinimumPrefetchInterval
	if len(source.urls) == 0 {
		return ttl, err
	}

	var bin, sig []byte
	for _, srcURL := range source.urls {
		dlog.Infof("Source [%s] loading from URL [%s]", source.name, srcURL)
		sigURL := &url.URL{}
		*sigURL = *srcURL // deep copy to avoid parsing twice
		sigURL.Path += ".minisig"
		if bin, err = fetchFromURL(xTransport, srcURL); err != nil {
			dlog.Debugf("Source [%s] failed to download from URL [%s]", source.name, srcURL)
			continue
		}
		if sig, err = fetchFromURL(xTransport, sigURL); err != nil {
			dlog.Debugf("Source [%s] failed to download signature from URL [%s]", source.name, sigURL)
			continue
		}
		if err = source.checkSignature(bin, sig); err != nil {
			dlog.Debugf("Source [%s] failed signature check using URL [%s]", source.name, srcURL)
			continue
		}
		break // valid signature
	}
	if err == nil {
		source.updateCache(bin, sig, now)
		ttl = source.cacheTTL
	}
	source.refresh = now.Add(ttl)
	return ttl, err
}

// NewSource loads a new source using the given cacheFile and urls, ensuring it has a valid signature
func NewSource(
	name string,
	xTransport *XTransport,
	urls []string,
	minisignKeyStr string,
	cacheFile string,
	formatStr string,
	refreshDelay time.Duration,
	prefix string,
) (*Source, error) {
	source := &Source{
		name:      name,
		urls:      []*url.URL{},
		cacheFile: cacheFile,
		cacheTTL:  refreshDelay,
		prefix:    prefix,
	}
	if formatStr == "v2" {
		source.format = SourceFormatV2
	} else {
		return source, fmt.Errorf("Unsupported source format: [%s]", formatStr)
	}
	if minisignKey, err := minisign.NewPublicKey(minisignKeyStr); err == nil {
		source.minisignKey = &minisignKey
	} else {
		return source, err
	}
	source.parseURLs(urls)
	now := timeNow()
	delay, err := source.fetchFromCache(now)
	if err == nil {
		dlog.Noticef("Source [%s] cache file [%s] loaded", source.name, source.cacheFile)
		if len(source.urls) > 0 {
			source.refresh = now.Add(delay)
		}
	} else {
		dlog.Debugf("Source [%s] cache file [%s] not present or invalid", source.name, source.cacheFile)
		if len(source.urls) > 0 {
			delay, err = source.fetchNew(xTransport, now)
			if err == nil {
				dlog.Noticef("Source [%s] fresh file [%s] loaded", source.name, source.cacheFile)
				source.refresh = now.Add(delay)
			}
		} else {
			dlog.Errorf("Source [%s] has no valid URL", source.name)
		}
	}
	return source, err
}

// PrefetchSources downloads latest versions of given sources, ensuring they have a valid signature before caching
func PrefetchSources(xTransport *XTransport, sources []*Source) (time.Duration, int) {
	var interval time.Duration
	now := timeNow()
	downloaded := 0
	for _, source := range sources {
		var delay time.Duration
		var err error
		if source.refresh.IsZero() {
			continue
		} else if source.refresh.After(now) {
			delay = source.refresh.Sub(now)
		} else {
			dlog.Debugf("Prefetching [%s]", source.name)
			if delay, err = source.fetchNew(xTransport, now); err != nil {
				dlog.Infof("Prefetching [%s] failed: %v, will retry in %v", source.name, err, delay)
			} else {
				dlog.Debugf("Prefetching [%s] succeeded, next update in %v", source.name, delay)
				downloaded++
			}
		}
		if interval == 0 || interval > delay {
			interval = delay
		}
	}
	if interval < MinimumPrefetchInterval {
		dlog.Debugf("Prefetching delay %v is ceiled to %v", interval, MinimumPrefetchInterval)
		interval = MinimumPrefetchInterval
	}
	return interval, downloaded
}

func (source *Source) Parse() ([]RegisteredServer, error) {
	if source.format == SourceFormatV2 {
		return source.parseV2()
	}
	dlog.Fatal("Unexpected source format")
	return []RegisteredServer{}, nil
}

func (source *Source) parseV2() ([]RegisteredServer, error) {
	var registeredServers []RegisteredServer
	var stampErrs []string
	appendStampErr := func(format string, a ...interface{}) {
		stampErr := fmt.Sprintf(format, a...)
		stampErrs = append(stampErrs, stampErr)
		dlog.Warn(stampErr)
	}
	in := string(source.bin)
	parts := strings.Split(in, "## ")
	if len(parts) < 2 {
		return registeredServers, fmt.Errorf("Invalid format for source at [%v]", source.urls)
	}
	parts = parts[1:]
	for _, part := range parts {
		part = strings.TrimSpace(part)
		subparts := strings.Split(part, "\n")
		if len(subparts) < 2 {
			return registeredServers, fmt.Errorf("Invalid format for source at [%v]", source.urls)
		}
		name := strings.TrimSpace(subparts[0])
		if len(name) == 0 {
			return registeredServers, fmt.Errorf("Invalid format for source at [%v]", source.urls)
		}
		subparts = subparts[1:]
		name = source.prefix + name
		var stampStr, description string
		stampStrs := make([]string, 0)
		for _, subpart := range subparts {
			subpart = strings.TrimSpace(subpart)
			if strings.HasPrefix(subpart, "sdns:") && len(subpart) >= 6 {
				stampStrs = append(stampStrs, subpart)
				continue
			} else if len(subpart) == 0 || strings.HasPrefix(subpart, "//") {
				continue
			}
			if len(description) > 0 {
				description += "\n"
			}
			description += subpart
		}
		stampStrsLen := len(stampStrs)
		if stampStrsLen <= 0 {
			appendStampErr("Missing stamp for server [%s]", name)
			continue
		} else if stampStrsLen > 1 {
			rand.Shuffle(stampStrsLen, func(i, j int) { stampStrs[i], stampStrs[j] = stampStrs[j], stampStrs[i] })
		}
		var stamp dnsstamps.ServerStamp
		var err error
		for _, stampStr = range stampStrs {
			stamp, err = dnsstamps.NewServerStampFromString(stampStr)
			if err == nil {
				break
			}
			appendStampErr("Invalid or unsupported stamp [%v]: %s", stampStr, err.Error())
		}
		if err != nil {
			continue
		}
		registeredServer := RegisteredServer{
			name: name, stamp: stamp, description: description,
		}
		dlog.Debugf("Registered [%s] with stamp [%s]", name, stamp.String())
		registeredServers = append(registeredServers, registeredServer)
	}
	if len(stampErrs) > 0 {
		return registeredServers, fmt.Errorf("%s", strings.Join(stampErrs, ", "))
	}
	return registeredServers, nil
}
