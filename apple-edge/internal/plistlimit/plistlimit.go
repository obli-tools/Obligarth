// Package plistlimit bounds the work needed to decode an untrusted property
// list. The decoder of the embedded libraries (micromdm/plist) builds the
// whole tree recursively, with no limit on nesting or size: Check makes one
// pass over the raw bytes, allocating nothing per element, and refuses a
// document whose nesting, element count or attributes exceed the limits
// before any decoder sees it. XML and binary property lists are covered.
package plistlimit

import (
	"bytes"
	"context"
	"errors"
)

// Limits bound a property list. Every limit must be positive.
type Limits struct {
	// MaxDepth bounds the nesting of elements (XML) or of objects
	// (binary), the root counting as 1.
	MaxDepth int
	// MaxElements bounds the nodes the decoder allocates: elements and
	// their attributes, comments, processing instructions and CDATA
	// sections (XML), or objects reached from the root (binary, where an
	// object referenced several times counts once per reference, as
	// decoders materialise it each time).
	MaxElements int
}

// Errors returned by Check (besides the error of the context).
var (
	ErrDepth     = errors.New("plistlimit: nesting too deep")
	ErrElements  = errors.New("plistlimit: too many elements")
	ErrExpansion = errors.New("plistlimit: binary property list expands too much")
	ErrSyntax    = errors.New("plistlimit: malformed or unsupported property list")
)

// Stats describes an accepted property list.
type Stats struct {
	Elements int  // nodes counted against Limits.MaxElements
	Depth    int  // deepest nesting reached
	Binary   bool // binary format ("bplist0")
}

// maxAttributes bounds the attributes of an XML element: a property list
// uses one ("version"); the decoder allocates them all in a single token.
const maxAttributes = 16

// ctxEvery is the number of bytes (XML) or objects (binary) between two
// checks of the context.
const ctxEvery = 64 << 10

// Check returns the statistics of b, or an error if b exceeds lim, is
// malformed as far as this pass can tell, or ctx ends first. It reads the
// document as the decoders do: the root element and what precedes it,
// nothing after.
func Check(ctx context.Context, b []byte, lim Limits) (Stats, error) {
	if lim.MaxDepth <= 0 || lim.MaxElements <= 0 {
		return Stats{}, errors.New("plistlimit: limits not set")
	}
	if bytes.HasPrefix(b, []byte("bplist0")) {
		return checkBinary(ctx, b, lim)
	}
	return checkXML(ctx, b, lim)
}

var (
	commentOpen  = []byte("<!--")
	commentClose = []byte("-->")
	cdataOpen    = []byte("<![CDATA[")
	cdataClose   = []byte("]]>")
	piOpen       = []byte("<?")
	piClose      = []byte("?>")
	doctypeOpen  = []byte("<!DOCTYPE")
)

// checkXML is a conservative lexer: markup that a property list never
// contains (DOCTYPE internal subset, other declarations, a DOCTYPE after the
// root, CDATA outside the root, attributes without quotes) is refused
// rather than interpreted, so that it never sees fewer elements than
// encoding/xml would.
func checkXML(ctx context.Context, b []byte, lim Limits) (Stats, error) {
	var st Stats
	depth, root, next := 0, false, 0
	for i := 0; i < len(b); {
		if i >= next {
			if err := ctx.Err(); err != nil {
				return st, err
			}
			next = i + ctxEvery
		}
		if b[i] != '<' {
			j := bytes.IndexByte(b[i:], '<')
			if j < 0 {
				break
			}
			i += j
			continue
		}
		rest := b[i:]
		var n int
		nodes, ok := 1, true // every markup but an end tag is a token of the decoder
		switch {
		case bytes.HasPrefix(rest, commentOpen):
			n, ok = skipPast(rest, len(commentOpen), commentClose)
		case bytes.HasPrefix(rest, cdataOpen):
			if depth == 0 {
				return st, ErrSyntax
			}
			n, ok = skipPast(rest, len(cdataOpen), cdataClose)
		case bytes.HasPrefix(rest, piOpen):
			n, ok = skipPast(rest, len(piOpen), piClose)
		case bytes.HasPrefix(rest, doctypeOpen):
			if root {
				return st, ErrSyntax
			}
			n, ok = skipDoctype(rest)
		case len(rest) > 1 && rest[1] == '!':
			return st, ErrSyntax
		case len(rest) > 1 && rest[1] == '/':
			nodes = 0
			if n, ok = endTag(rest); ok {
				if depth--; depth < 0 {
					return st, ErrSyntax
				}
			}
		default:
			var empty bool
			var attrs int
			if n, attrs, empty, ok = startTag(rest); ok {
				nodes += attrs
				if depth++; depth > lim.MaxDepth {
					return st, ErrDepth
				}
				st.Depth = max(st.Depth, depth)
				root = true
				if empty {
					depth--
				}
			}
		}
		if !ok {
			return st, ErrSyntax
		}
		if st.Elements += nodes; st.Elements > lim.MaxElements {
			return st, ErrElements
		}
		i += n
		if root && depth == 0 {
			return st, nil // decoders stop after the root element
		}
	}
	return st, ErrSyntax // no root element, or truncated
}

// skipPast returns the length of b up to and including the first end after
// offset from.
func skipPast(b []byte, from int, end []byte) (int, bool) {
	j := bytes.Index(b[from:], end)
	if j < 0 {
		return 0, false
	}
	return from + j + len(end), true
}

// skipDoctype accepts a DOCTYPE without internal subset (the one of
// property lists names an external DTD only).
func skipDoctype(b []byte) (int, bool) {
	var quote byte
	for i := len(doctypeOpen); i < len(b); i++ {
		c := b[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '>':
			return i + 1, true
		case c == '[' || c == '<':
			return 0, false
		}
	}
	return 0, false
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func nameStart(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_' || c == ':' || c >= 0x80
}

func nameChar(c byte) bool {
	return nameStart(c) || '0' <= c && c <= '9' || c == '-' || c == '.'
}

// name returns the end of the XML name starting at i (i if none).
func name(b []byte, i int) int {
	if i >= len(b) || !nameStart(b[i]) {
		return i
	}
	for i++; i < len(b) && nameChar(b[i]); i++ {
	}
	return i
}

func skipSpace(b []byte, i int) int {
	for i < len(b) && isSpace(b[i]) {
		i++
	}
	return i
}

// startTag scans "<name a='v' ...>" or "<name .../>".
func startTag(b []byte) (n, attrs int, empty, ok bool) {
	i := name(b, 1)
	if i == 1 {
		return 0, 0, false, false
	}
	for ; ; attrs++ {
		j := skipSpace(b, i)
		if j >= len(b) {
			return 0, 0, false, false
		}
		switch b[j] {
		case '>':
			return j + 1, attrs, false, true
		case '/':
			if j+1 < len(b) && b[j+1] == '>' {
				return j + 2, attrs, true, true
			}
			return 0, 0, false, false
		}
		if j == i || attrs == maxAttributes {
			return 0, 0, false, false
		}
		if i = name(b, j); i == j {
			return 0, 0, false, false
		}
		if i = skipSpace(b, i); i >= len(b) || b[i] != '=' {
			return 0, 0, false, false
		}
		if i = skipSpace(b, i+1); i >= len(b) || (b[i] != '"' && b[i] != '\'') {
			return 0, 0, false, false
		}
		v := bytes.IndexByte(b[i+1:], b[i])
		if v < 0 || bytes.IndexByte(b[i+1:i+1+v], '<') >= 0 {
			return 0, 0, false, false
		}
		i += v + 2
	}
}

// endTag scans "</name>", spaces allowed before ">".
func endTag(b []byte) (int, bool) {
	i := name(b, 2)
	if i == 2 {
		return 0, false
	}
	if i = skipSpace(b, i); i >= len(b) || b[i] != '>' {
		return 0, false
	}
	return i + 1, true
}

// checkBinary walks the object graph of a binary property list from its
// root, as the decoder does, without decoding values. It follows the
// format of CFBinaryPList: 8-byte header, objects, offset table, 32-byte
// trailer.
func checkBinary(ctx context.Context, b []byte, lim Limits) (Stats, error) {
	st := Stats{Binary: true}
	const header, trailer = 8, 32
	if len(b) < header+trailer {
		return st, ErrSyntax
	}
	t := b[len(b)-trailer:]
	offSize, refSize := uint64(t[6]), uint64(t[7])
	num, rootRef, table := beUint(t[8:16]), beUint(t[16:24]), beUint(t[24:32])
	end := uint64(len(b) - trailer)
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || table < header || table > end ||
		num == 0 || num > (end-table)/offSize || num > table-header || rootRef >= num {
		return st, ErrSyntax
	}
	// Bytes of strings and data materialised, a shared object counting
	// once per reference: a few times the document at most.
	budget := 8*uint64(len(b)) + 64<<10
	type frame struct {
		ref   uint64
		depth int
	}
	stack := []frame{{rootRef, 1}}
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if st.Elements++; st.Elements > lim.MaxElements {
			return st, ErrElements
		}
		if f.depth > lim.MaxDepth {
			return st, ErrDepth
		}
		st.Depth = max(st.Depth, f.depth)
		if st.Elements%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return st, err
			}
		}
		if f.ref >= num {
			return st, ErrSyntax
		}
		p := table + f.ref*offSize
		off := beUint(b[p : p+offSize])
		if off < header || off >= table {
			return st, ErrSyntax
		}
		marker := b[off]
		kind, low := marker>>4, uint64(marker&0x0f)
		p = off + 1
		switch kind {
		case 0x0: // null, false, true, fill
			if low != 0x0 && low != 0x8 && low != 0x9 && low != 0xf {
				return st, ErrSyntax
			}
		case 0x1, 0x2: // integer (up to 16 bytes), real (up to 8 bytes)
			if low > 4 || kind == 0x2 && low > 3 || p+(1<<low) > table {
				return st, ErrSyntax
			}
		case 0x3: // date
			if low != 0x3 || p+8 > table {
				return st, ErrSyntax
			}
		case 0x8: // UID
			if low > 7 || p+low+1 > table {
				return st, ErrSyntax
			}
		case 0xc: // set: not decoded
		case 0x4, 0x5, 0x6: // data, ASCII string, UTF-16 string
			count, q, ok := readCount(b, p, low, table)
			if !ok {
				return st, ErrSyntax
			}
			size := count
			if kind == 0x6 {
				if count > (table-q)/2 {
					return st, ErrSyntax
				}
				size = 2 * count
			}
			if size > table-q {
				return st, ErrSyntax
			}
			if size > budget {
				return st, ErrExpansion
			}
			budget -= size
		case 0xa, 0xd: // array, dictionary (keys then values)
			count, q, ok := readCount(b, p, low, table)
			if !ok {
				return st, ErrSyntax
			}
			refs := count
			if kind == 0xd {
				if count > (table-q)/2 {
					return st, ErrSyntax
				}
				refs = 2 * count
			}
			if refs > (table-q)/refSize {
				return st, ErrSyntax
			}
			if refs > uint64(lim.MaxElements-st.Elements-len(stack)) {
				return st, ErrElements
			}
			for k := uint64(0); k < refs; k++ {
				r := q + k*refSize
				stack = append(stack, frame{beUint(b[r : r+refSize]), f.depth + 1})
			}
		default:
			return st, ErrSyntax
		}
	}
	return st, nil
}

// readCount reads the length of a data, string or collection object whose
// marker's low nibble is low, its content starting at p.
func readCount(b []byte, p, low, table uint64) (count, q uint64, ok bool) {
	if low != 0x0f {
		return low, p, true
	}
	if p >= table {
		return 0, 0, false
	}
	n := uint64(1) << (b[p] & 0x0f)
	if n > 8 || p+1+n > table {
		return 0, 0, false
	}
	return beUint(b[p+1 : p+1+n]), p + 1 + n, true
}

func beUint(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}
