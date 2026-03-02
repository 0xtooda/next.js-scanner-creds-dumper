package main

import (
    "bufio"
    "flag"
    "fmt"
    "net"
    "os"
    "strings"
    "sync"
    "time"
)

func main() {
    concurrency := flag.Int("c", 512, "number of concurrent workers")
    port := flag.Int("p", 80, "port to scan")
    timeout := flag.Duration("t", 1000*time.Millisecond, "dial/read timeout")
    outPath := flag.String("o", "react.txt", "output file")
    flag.Parse()

    ips := make(chan string, *concurrency*2)
    results := make(chan string, *concurrency*2)

    var wg sync.WaitGroup
    wg.Add(*concurrency)
    for i := 0; i < *concurrency; i++ {
        go func() {
            defer wg.Done()
            for ip := range ips {
                if checkNextJS(ip, *port, *timeout) {
                    results <- fmt.Sprintf("%s:%d", ip, *port)
                }
            }
        }()
    }

    done := make(chan struct{})
    go func() {
        f, err := os.OpenFile(*outPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
        if err != nil {
            fmt.Fprintf(os.Stderr, "open %s: %v\n", *outPath, err)
            close(done)
            return
        }
        defer f.Close()
        for entry := range results {
            fmt.Printf("[+] %s\n", entry)
            _, _ = f.WriteString(entry + "\n")
            _ = f.Sync()
        }
        close(done)
    }()

    sc := bufio.NewScanner(os.Stdin)
    buf := make([]byte, 0, 64)
    sc.Buffer(buf, 1024)
    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if line == "" {
            continue
        }
        ips <- line
    }
    close(ips)
    wg.Wait()
    close(results)
    <-done
}

func checkNextJS(ip string, port int, timeout time.Duration) bool {
    addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
    d := net.Dialer{Timeout: timeout}
    conn, err := d.Dial("tcp", addr)
    if err != nil {
        return false
    }
    defer conn.Close()
    _ = conn.SetDeadline(time.Now().Add(timeout))
    req := "GET / HTTP/1.0\r\nHost: " + ip + "\r\nUser-Agent: Shodan-Pull/1.0\r\nConnection: close\r\n\r\n"
    if _, err = conn.Write([]byte(req)); err != nil {
        return false
    }
    reader := bufio.NewReader(conn)
    var headers strings.Builder
    const maxHeader = 32 * 1024
    for {
        line, err := reader.ReadString('\n')
        if err != nil {
            break
        }
        headers.WriteString(line)
        if headers.Len() > maxHeader {
            break
        }
        if strings.HasSuffix(headers.String(), "\r\n\r\n") || strings.HasSuffix(headers.String(), "\n\n") {
            break
        }
    }
    h := strings.ToLower(headers.String())
    if containsHeaderValue(h, "x-powered-by", "next.js") {
        return true
    }
    if strings.Contains(h, "x-powered-by: nextjs") || strings.Contains(h, "x-powered-by: next.js") {
        return true
    }
    return false
}

func containsHeaderValue(h string, key string, val string) bool {
    key = strings.ToLower(key)
    val = strings.ToLower(val)
    for _, line := range strings.Split(h, "\n") {
        ln := strings.TrimSpace(line)
        if ln == "" {
            continue
        }
        ln = strings.TrimSuffix(ln, "\r")
        if !strings.HasPrefix(ln, key+":") {
            continue
        }
        parts := strings.SplitN(ln, ":", 2)
        if len(parts) != 2 {
            continue
        }
        v := strings.TrimSpace(parts[1])
        if strings.Contains(strings.ToLower(v), val) {
            return true
        }
    }
    return false
}
