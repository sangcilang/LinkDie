// Package upload provides HTTP handlers and supporting types for the EphemeralShare
// upload pipeline, including ClamAV malware scanning.
package upload

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	// clamChunkSize is the size of each data chunk sent to clamd via INSTREAM.
	clamChunkSize = 4096

	// clamDialTimeout is the TCP connection timeout for clamd.
	clamDialTimeout = 5 * time.Second
)

// ClamAVClient is a minimal clamd TCP client that supports INSTREAM scanning.
type ClamAVClient struct {
	address string
}

// NewClamAVClient creates a new ClamAVClient that connects to the given clamd
// TCP address (e.g., "clamav:3310").
func NewClamAVClient(address string) *ClamAVClient {
	return &ClamAVClient{address: address}
}

// ScanReader streams the content of r to clamd via the INSTREAM protocol and
// returns whether the content is clean.
//
// Protocol:
//  1. Connect to clamd TCP socket.
//  2. Send "zINSTREAM\0" command (null-terminated).
//  3. Stream data in chunks: 4-byte big-endian length prefix + chunk data.
//  4. Send 4-byte zero (end of stream marker).
//  5. Read response: "stream: OK" = clean, "stream: {virus} FOUND" = infected.
//
// Returns:
//   - clean=true, virusName="", err=nil  → file is clean
//   - clean=false, virusName="...", err=nil → file is infected
//   - clean=false, virusName="", err=...  → scan error (connection, timeout, etc.)
func (c *ClamAVClient) ScanReader(ctx context.Context, r io.Reader) (clean bool, virusName string, err error) {
	// Derive a deadline from the context if it has one; otherwise use a generous default.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(60 * time.Second)
	}

	// Dial clamd.
	conn, err := net.DialTimeout("tcp", c.address, clamDialTimeout)
	if err != nil {
		return false, "", fmt.Errorf("clamav: failed to connect to %s: %w", c.address, err)
	}
	defer conn.Close()

	// Apply the overall deadline to the connection.
	if err := conn.SetDeadline(deadline); err != nil {
		return false, "", fmt.Errorf("clamav: failed to set deadline: %w", err)
	}

	// Send the INSTREAM command (null-terminated per clamd protocol).
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return false, "", fmt.Errorf("clamav: failed to send INSTREAM command: %w", err)
	}

	// Stream data in chunks.
	buf := make([]byte, clamChunkSize)
	lenBuf := make([]byte, 4)

	for {
		// Check context cancellation before each read.
		select {
		case <-ctx.Done():
			return false, "", fmt.Errorf("clamav: context cancelled during scan: %w", ctx.Err())
		default:
		}

		n, readErr := r.Read(buf)
		if n > 0 {
			// Write 4-byte big-endian chunk length.
			binary.BigEndian.PutUint32(lenBuf, uint32(n))
			if _, err := conn.Write(lenBuf); err != nil {
				return false, "", fmt.Errorf("clamav: failed to write chunk length: %w", err)
			}
			// Write chunk data.
			if _, err := conn.Write(buf[:n]); err != nil {
				return false, "", fmt.Errorf("clamav: failed to write chunk data: %w", err)
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return false, "", fmt.Errorf("clamav: error reading data to scan: %w", readErr)
		}
	}

	// Send end-of-stream marker: 4-byte zero.
	binary.BigEndian.PutUint32(lenBuf, 0)
	if _, err := conn.Write(lenBuf); err != nil {
		return false, "", fmt.Errorf("clamav: failed to send end-of-stream: %w", err)
	}

	// Read clamd response.
	response, err := io.ReadAll(conn)
	if err != nil {
		return false, "", fmt.Errorf("clamav: failed to read response: %w", err)
	}

	return parseClamdResponse(strings.TrimSpace(string(response)))
}

// parseClamdResponse interprets the clamd INSTREAM response string.
//
// Expected formats:
//   - "stream: OK"                    → clean
//   - "stream: {VirusName} FOUND"     → infected
//   - "stream: {error} ERROR"         → scan error
func parseClamdResponse(response string) (clean bool, virusName string, err error) {
	const prefix = "stream: "

	if !strings.HasPrefix(response, prefix) {
		return false, "", fmt.Errorf("clamav: unexpected response format: %q", response)
	}

	body := strings.TrimPrefix(response, prefix)

	switch {
	case body == "OK":
		return true, "", nil
	case strings.HasSuffix(body, " FOUND"):
		virus := strings.TrimSuffix(body, " FOUND")
		return false, virus, nil
	case strings.HasSuffix(body, " ERROR"):
		return false, "", fmt.Errorf("clamav: scan error: %s", body)
	default:
		return false, "", fmt.Errorf("clamav: unknown response: %q", response)
	}
}
