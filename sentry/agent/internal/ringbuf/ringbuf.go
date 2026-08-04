//go:build linux

// Package ringbuf drains captured events from the kernel.
package ringbuf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/sentry/agent/internal/attach"
	"github.com/sentry/agent/internal/identity"
	"github.com/sentry/agent/internal/ship"
)

// Field offsets in struct event (tls.bpf.c), for an aarch64/x86-64 layout.
//
// Decoded by hand rather than with binary.Read: that uses reflection, cannot
// set unexported padding fields, and panics on a struct that mirrors a C layout
// faithfully. It is also the hot path, and this avoids an allocation per event.
const (
	offWallNS      = 0
	offPID         = 8
	offCgroupID    = 16
	offDataLen     = 24
	offDPort       = 28
	offDAddr       = 32
	offDirection      = 36
	offDataClasses    = 37
	offIsRequest      = 38
	offIsContinuation = 39
	offFieldsLen      = 40
	// conn_key is 8-byte aligned, so the five bytes above it are followed by
	// seven of padding. Asserted against the object's own BTF in
	// offsets_test.go rather than trusted: every constant here is a hand-count
	// of a C layout, and a wrong one decodes silently into plausible garbage
	// rather than failing.
	offConnKey = 48
	headerLen  = 56

	// data[SCAN_BYTES] then fields[FIELDS_BYTES], both at the end of the record.
	scanBytes   = 512
	fieldsBytes = 128
	offFields   = headerLen + scanBytes
)

const (
	dirIngress = 1
	dirEgress  = 2
)

// Data-class bit positions, mirroring the BPF program.
var classNames = []struct {
	bit  uint8
	name string
}{
	{1 << 0, "PAN"},
	{1 << 1, "AADHAAR"},
	{1 << 2, "IFSC"},
	{1 << 3, "ACCOUNT_NO"},
	{1 << 4, "CARD"},
	{1 << 5, "CVV"},
	{1 << 6, "DOB"},
}

// monotonicEpoch is the wall-clock instant at which CLOCK_MONOTONIC read zero.
//
// bpf_ktime_get_ns() returns CLOCK_MONOTONIC, which counts from boot and not
// from 1970. Read as epoch nanoseconds it put every observation in January
// 1970 — vday survived, because the ingest stamps that from the shared clock,
// but wall_ts and the hour-of-day histogram built on it did not.
//
// There is no BPF helper that returns wall time on the kernels this targets, so
// the conversion belongs here. Anchoring once at startup rather than per event
// also keeps the offset consistent across a batch.
func monotonicEpoch() time.Time {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// Leaves timestamps as the kernel reported them rather than inventing an
		// offset. Wrong by a known constant beats wrong by an unknown one.
		return time.Unix(0, 0)
	}
	return time.Now().Add(-time.Duration(ts.Nano()))
}

type Consumer struct {
	rd    *ringbuf.Reader
	ship  *ship.Shipper
	ident *identity.Resolver
	log   *slog.Logger

	// Added to each event's monotonic timestamp to get wall time.
	epoch time.Time

	// Read from the kernel's own counter. If userspace cannot keep up, this
	// rises and the console shows capture as degraded rather than presenting an
	// undercount as a complete picture.
	lost atomic.Uint64
}

func New(objs *attach.Objects, s *ship.Shipper, ident *identity.Resolver, log *slog.Logger) (*Consumer, error) {
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, err
	}
	return &Consumer{rd: rd, ship: s, ident: ident, log: log, epoch: monotonicEpoch()}, nil
}

func (c *Consumer) Lost() uint64 { return c.lost.Load() }

func (c *Consumer) Run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = c.rd.Close()
	}()

	for {
		rec, err := c.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			c.log.Warn("ringbuf read", "err", err)
			continue
		}
		c.lost.Add(uint64(rec.Remaining))

		obs, ok := c.decode(rec.RawSample)
		if !ok {
			continue
		}
		c.ship.Enqueue(obs)
	}
}

func (c *Consumer) decode(raw []byte) (ship.Observation, bool) {
	if len(raw) < headerLen {
		return ship.Observation{}, false
	}
	le := binary.LittleEndian

	dataLen := int(le.Uint32(raw[offDataLen:]))
	payload := raw[headerLen:]
	if dataLen < len(payload) {
		payload = payload[:dataLen]
	}

	obs := ship.Observation{
		WallUnixNS:  c.epoch.Add(time.Duration(le.Uint64(raw[offWallNS:]))).UnixNano(),
		PID:         le.Uint32(raw[offPID:]),
		CgroupID:    le.Uint64(raw[offCgroupID:]),
		Port:        uint32(le.Uint16(raw[offDPort:])),
		DataClasses: decodeClasses(raw[offDataClasses]),
		ConnKey:     le.Uint64(raw[offConnKey:]),
	}

	obs.ResponseFields = decodeFields(raw, int(raw[offFieldsLen]))

	// A body write joined to a header already reported. It carries no bytes of
	// the body — only the class mask and the names of its JSON keys — and exists
	// to be merged into that observation.
	if raw[offIsContinuation] == 1 {
		obs.Continuation = true
		return obs, len(obs.DataClasses) > 0 || len(obs.ResponseFields) > 0
	}

	if addr := le.Uint32(raw[offDAddr:]); addr != 0 {
		var ip [4]byte
		le.PutUint32(ip[:], addr)
		obs.PeerIP = net.IP(ip[:]).String()
	}

	if raw[offDirection] == dirIngress {
		obs.Direction = "INGRESS"
	} else {
		obs.Direction = "EGRESS"
	}

	if raw[offIsRequest] == 1 {
		parseRequest(string(payload), &obs)

		// Name the caller.
		//
		// Only an egress request can do this. SSL_write carrying a request line
		// is the client half of the exchange, so the process the kernel sampled
		// is the one making the call — its cgroup names the calling service. The
		// ingress copy of the same request is the server reading it, where the
		// local process is the callee and the peer is whoever connected; the
		// connect kprobe is client-side, so that direction has no peer address
		// to resolve and the field is correctly left unset rather than filled
		// with the callee's own name.
		if obs.Direction == "EGRESS" {
			obs.PeerService = c.ident.Lookup(obs.CgroupID, obs.PID)
		}
	} else {
		parseResponse(string(payload), &obs)
	}

	// A record that parsed as neither a request nor a response carries nothing
	// the pipeline can use.
	return obs, obs.Method != "" || obs.Status != 0
}

func decodeClasses(mask uint8) []string {
	var out []string
	for _, c := range classNames {
		if mask&c.bit != 0 {
			out = append(out, c.name)
		}
	}
	return out
}

// decodeFields splits the kernel's NUL-separated key names.
//
// Names only. The BPF side rewinds any token that turns out to be a value
// before the next byte is read, so there is nothing here to filter out — but
// this is also the last point at which a value could enter the pipeline, so the
// length is bounded and anything non-printable is dropped rather than trusted.
func decodeFields(raw []byte, n int) []string {
	if n <= 0 || len(raw) < offFields+fieldsBytes {
		return nil
	}
	if n > fieldsBytes {
		n = fieldsBytes
	}

	var out []string
	seen := make(map[string]struct{}, 8)
	for _, part := range bytes.Split(raw[offFields:offFields+n], []byte{0}) {
		name := strings.TrimSpace(string(part))
		if name == "" || len(name) > 64 {
			continue
		}
		if strings.IndexFunc(name, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
			continue
		}
		// Lower-cased so `accountNumber` and `accountnumber` are one shingle:
		// the fingerprint compares across services written by different teams,
		// and a casing difference is not a schema difference.
		name = strings.ToLower(name)
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out) // stable order, so identical bodies hash identically
	return out
}

func parseRequest(s string, obs *ship.Observation) {
	line, rest, _ := strings.Cut(s, "\r\n")
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	obs.Method = parts[0]
	obs.PathRaw = parts[1]
	if i := strings.IndexByte(obs.PathRaw, '?'); i >= 0 {
		obs.PathRaw = obs.PathRaw[:i]
	}

	for _, hdr := range strings.Split(rest, "\r\n") {
		name, value, ok := strings.Cut(hdr, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "host":
			obs.Host = value
		case "authorization":
			obs.AuthPresent = true
			// The scheme is recorded; the credential never leaves this function.
			if scheme, _, ok := strings.Cut(value, " "); ok {
				obs.AuthScheme = strings.ToLower(scheme)
			} else {
				obs.AuthScheme = "unknown"
			}
		case "soapaction":
			obs.PathRaw += "#" + strings.Trim(value, `"`)
		case "x-sentry-synthetic":
			// Traffic the platform generated to test itself. Recorded rather
			// than dropped — an operator asking why a judged endpoint shows a
			// spike deserves to see it — but excluded from every usage figure.
			obs.Synthetic = true
		}
	}
}

func parseResponse(s string, obs *ship.Observation) {
	line, _, _ := strings.Cut(s, "\r\n")
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	var code int
	for _, ch := range parts[1] {
		if ch < '0' || ch > '9' {
			return
		}
		code = code*10 + int(ch-'0')
	}
	obs.Status = uint32(code)
}
