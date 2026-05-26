package util

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
)

// Sentinel errors for MIME and ZIP validation.
var (
	ErrMIMEMismatch    = errors.New("detected MIME type does not match declared content type")
	ErrMIMENotAllowed  = errors.New("MIME type is not in the allowed list")
	ErrZipBombDetected = errors.New("ZIP bomb detected")
)

// allowedMIMETypes is the hardcoded list of permitted MIME types.
var allowedMIMETypes = map[string]bool{
	"application/pdf":              true,
	"application/zip":              true,
	"application/x-zip-compressed": true,
	"application/msword":           true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": true,
	"application/vnd.ms-excel": true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         true,
	"application/vnd.ms-powerpoint":                                              true,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,
	"image/jpeg":      true,
	"image/png":       true,
	"image/gif":       true,
	"image/webp":      true,
	"image/svg+xml":   true,
	"text/plain":      true,
	"text/csv":        true,
	"video/mp4":       true,
	"video/webm":      true,
	"audio/mpeg":      true,
	"audio/ogg":       true,
	"audio/wav":       true,
}

// officeDocumentMIMETypes are ZIP-based Office formats. net/http.DetectContentType
// will sniff these as "application/zip", which is acceptable.
var officeDocumentMIMETypes = map[string]bool{
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         true,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,
	"application/msword":           true,
	"application/vnd.ms-excel":     true,
	"application/vnd.ms-powerpoint": true,
}

// nestedZipExtensions are extensions that indicate a nested ZIP/Office archive.
var nestedZipExtensions = []string{".zip", ".docx", ".xlsx", ".pptx"}

// ValidateMIME sniffs the first 512 bytes of header and validates the content type.
// It checks:
//  1. The sniffed type is in the allowed list.
//  2. The sniffed type is compatible with the declared type.
//
// For ZIP-based Office documents, net/http.DetectContentType returns "application/zip",
// which is considered compatible with any declared Office MIME type.
func ValidateMIME(header []byte, declaredType string) error {
	// Sniff up to 512 bytes.
	sniffBuf := header
	if len(sniffBuf) > 512 {
		sniffBuf = sniffBuf[:512]
	}

	detected := http.DetectContentType(sniffBuf)
	// DetectContentType may return types with parameters (e.g. "text/plain; charset=utf-8").
	// Strip parameters for comparison.
	detected = strings.ToLower(strings.TrimSpace(strings.Split(detected, ";")[0]))
	declared := strings.ToLower(strings.TrimSpace(strings.Split(declaredType, ";")[0]))

	// Check declared type is in the allowed list.
	if !allowedMIMETypes[declared] {
		return ErrMIMENotAllowed
	}

	// Check detected type is in the allowed list.
	if !allowedMIMETypes[detected] {
		return ErrMIMENotAllowed
	}

	// Check compatibility between detected and declared types.
	if detected == declared {
		return nil
	}

	// ZIP-based Office documents are sniffed as "application/zip" — this is acceptable.
	if detected == "application/zip" || detected == "application/x-zip-compressed" {
		if officeDocumentMIMETypes[declared] || declared == "application/zip" || declared == "application/x-zip-compressed" {
			return nil
		}
	}

	// application/zip and application/x-zip-compressed are interchangeable.
	if (declared == "application/zip" && detected == "application/x-zip-compressed") ||
		(declared == "application/x-zip-compressed" && detected == "application/zip") {
		return nil
	}

	// text/csv is often sniffed as text/plain — treat as compatible.
	if declared == "text/csv" && detected == "text/plain" {
		return nil
	}

	return ErrMIMEMismatch
}

// ValidateOfficeDocument reads r as a ZIP archive and applies zip bomb protections:
//   - Max 1000 ZIP entries
//   - Max 100× compression ratio per entry (uncompressed / compressed size)
//   - No nested ZIP/Office archives (entries ending in .zip, .docx, .xlsx, .pptx)
//   - Max 2× declaredSize uncompressed total
//
// Returns ErrZipBombDetected if any limit is exceeded, or a wrapped error on read failure.
func ValidateOfficeDocument(r io.Reader, declaredSize int64) error {
	const (
		maxEntries          = 1000
		maxCompressionRatio = 100
	)

	// Read the entire content into memory so we can pass it to zip.NewReader.
	// We limit the read to avoid excessive memory usage (2× declared size + 1 MB buffer).
	maxRead := declaredSize*2 + 1<<20 // 2× declared + 1 MiB
	if maxRead < 1<<20 {
		maxRead = 1 << 20 // minimum 1 MiB
	}
	limitedReader := io.LimitReader(r, maxRead+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return err
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}

	if len(zr.File) > maxEntries {
		return ErrZipBombDetected
	}

	var totalUncompressed int64
	for _, f := range zr.File {
		// Check for nested ZIP/Office archives.
		nameLower := strings.ToLower(f.Name)
		for _, ext := range nestedZipExtensions {
			if strings.HasSuffix(nameLower, ext) {
				return ErrZipBombDetected
			}
		}

		// Check per-entry compression ratio.
		compressedSize := int64(f.CompressedSize64)
		uncompressedSize := int64(f.UncompressedSize64)

		if compressedSize > 0 && uncompressedSize > compressedSize*maxCompressionRatio {
			return ErrZipBombDetected
		}

		totalUncompressed += uncompressedSize
	}

	// Check total uncompressed size against declared file size.
	if declaredSize > 0 && totalUncompressed > declaredSize*2 {
		return ErrZipBombDetected
	}

	return nil
}
