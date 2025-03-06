# Xss
This script is designed to be fast and efficient, leveraging Go's concurrency features to check multiple URLs simultaneously.
Explanation:

    Reading URLs from a file: The script reads URLs from a file specified by the user.

    Filtering URLs: It filters out URLs that contain certain file extensions.

    Modifying URLs: It replaces the query string with a payload ("><()).

    Checking for vulnerability: It concurrently checks if the payload is reflected in the response, indicating a potential XSS vulnerability.

  Usage:

    Save the script to a file, e.g., xss.go.

    Compile the script using go build xss.go.

    Run the compiled binary, e.g., ./xss.

    Enter the file name containing the URLs when prompted.
