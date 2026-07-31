package race

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/HOLYAC/h1-racer-kernel/internal/protocol"
	"github.com/HOLYAC/h1-racer-kernel/internal/transport"
)

type prepareOutcome struct {
	index int
	ready bool
	error string
}

func Run(parent context.Context, plan protocol.CompiledPlan) protocol.RaceReport {
	startedWall := time.Now().UTC()
	started := time.Now()
	report := protocol.RaceReport{
		SchemaVersion: protocol.SchemaVersion,
		Target:        plan.Target,
		Copies:        plan.Copies,
		StartedAtUTC:  startedWall,
		Connections:   make([]protocol.ConnectionResult, plan.Copies),
	}
	factory, err := transport.NewFactory(plan)
	if err != nil {
		report.AbortError = err.Error()
		report.CompletedAtUTC = time.Now().UTC()
		return report
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	prepared := make(chan prepareOutcome, plan.Copies)
	finished := make(chan protocol.ConnectionResult, plan.Copies)
	fire := make(chan struct{})
	var releaseAfterStart atomic.Int64

	for index := 0; index < plan.Copies; index++ {
		go worker(ctx, index, started, plan, factory, fire, &releaseAfterStart, prepared, finished)
	}

	var firstPrepareError string
	for range plan.Copies {
		outcome := <-prepared
		if outcome.ready {
			report.ReadyCount++
		} else if firstPrepareError == "" {
			firstPrepareError = fmt.Sprintf("connection %d: %s", outcome.index, outcome.error)
			cancel()
		}
	}

	if firstPrepareError != "" {
		report.AbortError = firstPrepareError
		cancel()
	} else {
		if plan.Settle > 0 {
			timer := time.NewTimer(plan.Settle)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
			}
		}
		releaseNS := time.Since(started).Nanoseconds()
		releaseAfterStart.Store(releaseNS)
		report.ReleaseAfterStartNS = int64Pointer(releaseNS)
		report.Fired = true
		close(fire)
	}

	for range plan.Copies {
		result := <-finished
		report.Connections[result.Index] = result
	}
	report.ClientSendSpreadNS = sendSpread(report.Connections)
	report.CompletedAtUTC = time.Now().UTC()
	return report
}

func worker(
	ctx context.Context,
	index int,
	started time.Time,
	plan protocol.CompiledPlan,
	factory *transport.Factory,
	fire <-chan struct{},
	releaseAfterStart *atomic.Int64,
	prepared chan<- prepareOutcome,
	finished chan<- protocol.ConnectionResult,
) {
	result := protocol.ConnectionResult{Index: index, Phase: "connect"}
	preparedSent := false
	defer func() {
		if !preparedSent {
			prepared <- prepareOutcome{index: index, error: result.Error}
		}
		finishedNS := time.Since(started).Nanoseconds()
		result.FinishedAfterStartNS = int64Pointer(finishedNS)
		finished <- result
	}()

	conn, err := factory.Open(ctx)
	if err != nil {
		result.Error = err.Error()
		return
	}
	defer conn.Conn.Close()
	connectedNS := conn.ConnectedAt.Sub(started).Nanoseconds()
	result.ConnectedAfterStartNS = int64Pointer(connectedNS)
	if conn.HandshakeAt != nil {
		handshakeNS := conn.HandshakeAt.Sub(started).Nanoseconds()
		result.HandshakeAfterStartNS = int64Pointer(handshakeNS)
	}
	result.LocalAddress = conn.LocalAddress
	result.RemoteAddress = conn.RemoteAddress
	result.TLSVersion = conn.TLSVersion
	result.CipherSuite = conn.CipherSuite
	result.ALPN = conn.ALPN
	result.CertificateVerified = conn.CertificateVerified
	result.TLSIdentitySource = conn.TLSIdentitySource
	result.TLSProfile = conn.TLSProfile
	result.ClientHelloBytes = conn.ClientHelloBytes
	result.ClientHelloSHA256 = conn.ClientHelloSHA256
	result.ClientHelloJA3 = conn.ClientHelloJA3
	result.ClientHelloJA3SHA256 = conn.ClientHelloJA3SHA256
	result.ClientHelloRecordCount = conn.ClientHelloRecordCount

	result.Phase = "arm"
	if err = transport.WriteAll(conn.Conn, plan.Prefix, plan.IOTimeout); err != nil {
		result.Error = fmt.Sprintf("write prefix: %v", err)
		return
	}
	armedNS := time.Since(started).Nanoseconds()
	result.ArmedAfterStartNS = int64Pointer(armedNS)
	prepared <- prepareOutcome{index: index, ready: true}
	preparedSent = true

	result.Phase = "ready"
	select {
	case <-fire:
	case <-ctx.Done():
		result.Phase = "aborted"
		result.Error = "race aborted before FIRE"
		return
	}

	result.Phase = "fire"
	if err = transport.WriteAll(conn.Conn, plan.Suffix, plan.IOTimeout); err != nil {
		result.Error = fmt.Sprintf("write suffix: %v", err)
		return
	}
	sentAfterStart := time.Since(started).Nanoseconds()
	sentAfterRelease := sentAfterStart - releaseAfterStart.Load()
	result.SuffixSentAfterReleaseNS = int64Pointer(sentAfterRelease)

	result.Phase = "response"
	response, endedBy, readErr := transport.ReadRaw(conn.Conn, plan.MaxResponseBytes, plan.IOTimeout)
	result.ResponseBytes = len(response)
	result.ResponseEndedBy = endedBy
	if len(response) > 0 {
		digest := sha256.Sum256(response)
		result.ResponseSHA256 = fmt.Sprintf("%x", digest[:])
		result.ResponseBase64 = base64.StdEncoding.EncodeToString(response)
	}
	if readErr != nil {
		result.Error = readErr.Error()
		return
	}
	result.Phase = "complete"
}

func sendSpread(results []protocol.ConnectionResult) *int64 {
	values := make([]int64, 0, len(results))
	for _, result := range results {
		if result.SuffixSentAfterReleaseNS != nil {
			values = append(values, *result.SuffixSentAfterReleaseNS)
		}
	}
	if len(values) < 2 {
		return nil
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	spread := values[len(values)-1] - values[0]
	return &spread
}

func int64Pointer(value int64) *int64 {
	return &value
}
