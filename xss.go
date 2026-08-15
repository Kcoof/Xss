// xss — fast mass XSS reflection pre-filter by Kcoof.
//
// Reads URLs (file or stdin), injects a probe payload into FUZZ placeholders
// or every query parameter, and reports which URLs reflect the payload back.
//
//	This is a SPEED filter, not a verifier: a reflection means the URL is worth
//	deep-testing with context-aware analysis in
//	https://github.com/Kcoof/security-scanner (secscan).
//
// Usage:
//	cat urls.txt | xss -                     # pipe-friendly
//	xss -l urls.txt -o reflecting.txt        # save hits
//	xss -l urls.txt -p '"><img src=x>' -t 40
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const version = "2.0.0"
const defaultPayload = `"><()kcoof`

var skipExtensions = []string{
	".jpg", ".jpeg", ".js", ".css", ".gif", ".tif", ".tiff", ".png",
	".woff", ".woff2", ".ico", ".pdf", ".svg", ".txt", ".mp4", ".mp3",
	".zip", ".gz", ".rar", ".7z",
}

var (
	flagList    string
	flagOut     string
	flagPayload string
	flagUA      string
	flagThreads int
	flagTimeout int
	flagAll     bool
	flagVersion bool
)

type task struct {
	requestURL string // URL with payload injected
	originURL  string // original URL as read
	param      string // "FUZZ" placeholder or parameter name
}

type hit struct {
	task
	reflected bool
}

func main() {
	flag.StringVar(&flagList, "l", "", "File with URLs, or - for stdin")
	flag.StringVar(&flagOut, "o", "", "Save reflecting URLs to this file")
	flag.StringVar(&flagPayload, "p", defaultPayload, "Probe payload")
	flag.StringVar(&flagUA, "ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", "User-Agent")
	flag.IntVar(&flagThreads, "t", 20, "Concurrent workers")
	flag.IntVar(&flagTimeout, "timeout", 10, "Request timeout in seconds")
	flag.BoolVar(&flagAll, "a", false, "Print non-reflecting URLs too")
	flag.BoolVar(&flagVersion, "version", false, "Print version")
	flag.Parse()

	if flagVersion {
		fmt.Println("xss", version)
		return
	}
	if flagList == "" {
		fmt.Fprintln(os.Stderr, "Usage: xss -l urls.txt  (or pipe: cat urls.txt | xss -)")
		fmt.Fprintln(os.Stderr, "Run xss -h for all options.")
		os.Exit(1)
	}

	urls, err := readInput(flagList)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Reading input: %v\n", err)
		os.Exit(1)
	}

	tasks := buildTasks(urls)
	fmt.Fprintf(os.Stderr, "[*] %d URLs in, %d testable parameter positions\n", len(urls), len(tasks))

	client := &http.Client{
		Timeout: time.Duration(flagTimeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // reflection happens on first response
		},
	}

	jobs := make(chan task)
	results := make(chan hit)
	var wg sync.WaitGroup
	var stdout sync.Mutex
	var reflecting []string

	for i := 0; i < flagThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				results <- hit{task: t, reflected: reflects(client, t.requestURL)}
			}
		}()
	}

	go func() {
		for _, t := range tasks {
			jobs <- t
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	count := 0
	for r := range results {
		if r.reflected {
			count++
			reflecting = append(reflecting, r.requestURL)
			stdout.Lock()
			fmt.Printf("\033[91m[REFLECTS]\033[0m %s  (param: %s)\n", r.requestURL, r.param)
			stdout.Unlock()
		} else if flagAll {
			stdout.Lock()
			fmt.Printf("\033[92m[  clean ]\033[0m %s\n", r.requestURL)
			stdout.Unlock()
		}
	}

	fmt.Fprintf(os.Stderr, "[+] Done: %d/%d positions reflect the payload\n", count, len(tasks))

	if flagOut != "" && len(reflecting) > 0 {
		if err := writeLines(reflecting, flagOut); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[+] Reflecting URLs saved to %s — verify with: python -m secscan %s\n", flagOut, flagOut)
	}
}

// buildTasks turns input URLs into per-position test tasks. URLs containing
// the FUZZ placeholder get exactly that replaced; URLs with a query string
// get each parameter value replaced one at a time.
func buildTasks(urls []string) []task {
	var tasks []task
	seen := map[string]bool{}
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" || !strings.HasPrefix(raw, "http") {
			continue
		}
		if hasSkipExtension(raw) {
			continue
		}
		if strings.Contains(raw, "FUZZ") {
			t := task{requestURL: strings.ReplaceAll(raw, "FUZZ", flagPayload), originURL: raw, param: "FUZZ"}
			if !seen[t.requestURL] {
				seen[t.requestURL] = true
				tasks = append(tasks, t)
			}
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.RawQuery == "" {
			continue
		}
		query := parsed.Query()
		for param := range query {
			modified := url.Values{}
			for k, values := range query {
				if k == param {
					modified.Set(k, flagPayload)
				} else {
					modified[k] = values
				}
			}
			clone := *parsed
			clone.RawQuery = modified.Encode()
			t := task{requestURL: clone.String(), originURL: raw, param: param}
			if !seen[t.requestURL] {
				seen[t.requestURL] = true
				tasks = append(tasks, t)
			}
		}
	}
	return tasks
}

func reflects(client *http.Client, target string) bool {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", flagUA)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return false
	}
	return strings.Contains(string(body), flagPayload)
}

func hasSkipExtension(raw string) bool {
	lower := strings.ToLower(raw)
	for _, ext := range skipExtensions {
		if strings.Contains(lower, ext) {
			return true
		}
	}
	return false
}

func readInput(source string) ([]string, error) {
	var reader io.Reader
	if source == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(source)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		reader = file
	}
	var lines []string
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, line := range lines {
		fmt.Fprintln(file, line)
	}
	return nil
}
