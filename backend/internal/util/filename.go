package util

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// ErrEmptyFilename is returned when the filename is empty after sanitization.
var ErrEmptyFilename = errors.New("filename is empty after sanitization")

// rtlOverrideChars are Unicode characters used to override text direction.
var rtlOverrideChars = map[rune]bool{
	'\u202E': true, // RIGHT-TO-LEFT OVERRIDE
	'\u200F': true, // RIGHT-TO-LEFT MARK
	'\u202B': true, // RIGHT-TO-LEFT EMBEDDING
}

// invisibleChars are Unicode characters that are invisible but can be used for spoofing.
var invisibleChars = map[rune]bool{
	'\u200B': true, // ZERO WIDTH SPACE
	'\uFEFF': true, // ZERO WIDTH NO-BREAK SPACE (BOM)
	'\u00AD': true, // SOFT HYPHEN
}

// pathSeparatorChars are characters that are illegal in filenames or used as path separators.
var pathSeparatorChars = map[rune]bool{
	'/':  true,
	'\\': true,
	':':  true,
	'*':  true,
	'?':  true,
	'"':  true,
	'<':  true,
	'>':  true,
	'|':  true,
}

// SanitizeFilename sanitizes a filename by:
//  1. Applying NFC Unicode normalization.
//  2. Stripping RTL override characters (U+202E, U+200F, U+202B).
//  3. Stripping invisible characters (U+200B, U+FEFF, U+00AD).
//  4. Stripping control characters (runes < 0x20 and 0x7F).
//  5. Stripping path separators and illegal filename characters.
//  6. Enforcing a maximum of 255 bytes (truncating without splitting multi-byte runes).
//
// Returns ErrEmptyFilename if the result is empty after sanitization.
func SanitizeFilename(filename string) (string, error) {
	// Step 1: NFC normalization.
	normalized := norm.NFC.String(filename)

	// Step 2–5: Filter characters.
	var sb strings.Builder
	sb.Grow(len(normalized))

	for _, r := range normalized {
		// Strip RTL override characters.
		if rtlOverrideChars[r] {
			continue
		}
		// Strip invisible characters.
		if invisibleChars[r] {
			continue
		}
		// Strip control characters (< 0x20 and DEL 0x7F).
		if r < 0x20 || r == 0x7F {
			continue
		}
		// Strip path separators and illegal filename characters.
		if pathSeparatorChars[r] {
			continue
		}
		// Strip other non-printable Unicode characters.
		if !unicode.IsPrint(r) {
			continue
		}
		sb.WriteRune(r)
	}

	result := sb.String()

	// Step 6: Enforce max 255 bytes without splitting multi-byte runes.
	if len(result) > 255 {
		result = truncateToBytes(result, 255)
	}

	if result == "" {
		return "", ErrEmptyFilename
	}

	return result, nil
}

// truncateToBytes truncates s to at most maxBytes bytes without splitting a multi-byte rune.
func truncateToBytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Walk rune by rune and stop before exceeding maxBytes.
	n := 0
	for i := 0; i < len(s); {
		_, size := utf8.DecodeRuneInString(s[i:])
		if n+size > maxBytes {
			break
		}
		n += size
		i += size
	}
	return s[:n]
}
