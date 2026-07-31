package protocol

import "time"

type ConnectionResult struct {
	Index                    int    `json:"index"`
	Phase                    string `json:"phase"`
	LocalAddress             string `json:"local_address,omitempty"`
	RemoteAddress            string `json:"remote_address,omitempty"`
	TLSVersion               string `json:"tls_version,omitempty"`
	CipherSuite              string `json:"cipher_suite,omitempty"`
	ALPN                     string `json:"alpn,omitempty"`
	ConnectedAfterStartNS    *int64 `json:"connected_after_start_ns,omitempty"`
	HandshakeAfterStartNS    *int64 `json:"handshake_after_start_ns,omitempty"`
	ArmedAfterStartNS        *int64 `json:"armed_after_start_ns,omitempty"`
	SuffixSentAfterReleaseNS *int64 `json:"suffix_sent_after_release_ns,omitempty"`
	FinishedAfterStartNS     *int64 `json:"finished_after_start_ns,omitempty"`
	ResponseBytes            int    `json:"response_bytes"`
	ResponseSHA256           string `json:"response_sha256,omitempty"`
	ResponseBase64           string `json:"response_base64,omitempty"`
	ResponseEndedBy          string `json:"response_ended_by,omitempty"`
	Error                    string `json:"error,omitempty"`
}

type RaceReport struct {
	SchemaVersion       int                `json:"schema_version"`
	Target              string             `json:"target"`
	Copies              int                `json:"copies"`
	ReadyCount          int                `json:"ready_count"`
	Fired               bool               `json:"fired"`
	AbortError          string             `json:"abort_error,omitempty"`
	StartedAtUTC        time.Time          `json:"started_at_utc"`
	CompletedAtUTC      time.Time          `json:"completed_at_utc"`
	ReleaseAfterStartNS *int64             `json:"release_after_start_ns,omitempty"`
	ClientSendSpreadNS  *int64             `json:"client_send_spread_ns,omitempty"`
	Connections         []ConnectionResult `json:"connections"`
}
