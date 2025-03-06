package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
)

const payload = `"><()`

func main() {
	// Ask for the file name from the terminal
	fmt.Print("Enter the file name containing URLs: ")
	var fileName string
	fmt.Scanln(&fileName)

	// Read URLs from the file
	urls, err := readURLsFromFile(fileName)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	// Filter URLs
	filteredURLs := filterURLs(urls)

	// Replace query strings with payload
	modifiedURLs := modifyURLs(filteredURLs)

	// Check for vulnerability
	var wg sync.WaitGroup
	results := make(chan string)

	for _, url := range modifiedURLs {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			if isVulnerable(u) {
				results <- fmt.Sprintf("%s \033[91m Vulnerable \033[0m\n", u)
			} else {
				results <- fmt.Sprintf("%s \033[92m Not Vulnerable \033[0m\n", u)
			}
		}(url)
	}

	// Close the results channel when all goroutines are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Print results
	for result := range results {
		fmt.Print(result)
	}
}

func readURLsFromFile(fileName string) ([]string, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

func filterURLs(urls []string) []string {
	extensions := []string{".jpg", ".jpeg", ".js", ".css", ".gif", ".tif", ".tiff", ".png", ".woff", ".woff2", ".ico", ".pdf", ".svg", ".txt"}
	var filtered []string

	for _, url := range urls {
		shouldExclude := false
		for _, ext := range extensions {
			if strings.Contains(strings.ToLower(url), ext) {
				shouldExclude = true
				break
			}
		}
		if !shouldExclude {
			filtered = append(filtered, url)
		}
	}

	return filtered
}

func modifyURLs(urls []string) []string {
	var modified []string
	for _, url := range urls {
		modified = append(modified, strings.Replace(url, "FUZZ", payload, -1))
	}
	return modified
}

func isVulnerable(url string) bool {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	return strings.Contains(string(body), payload)
}
