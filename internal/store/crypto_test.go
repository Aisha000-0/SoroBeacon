package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testConfigKey is a 32-byte AES-256 key used across the crypto tests.
const testConfigKey = "0123456789abcdef0123456789abcdef"

func testCipher(t *testing.T, key string) *AESGCMCipher {
	t.Helper()
	cp, err := NewAESGCMCipher([]byte(key))
	require.NoError(t, err)
	return cp
}

func TestAESGCMCipherRoundTrip(t *testing.T) {
	c := testCipher(t, testConfigKey)
	plaintext := []byte(`{"url":"https://hooks.example/T000/B000/secret","token":"s3cr3t"}`)

	sealed, err := c.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, sealed)
	assert.NotContains(t, string(sealed), "s3cr3t")

	got, err := c.Decrypt(sealed)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	// A fresh nonce per call means sealing the same plaintext twice never
	// produces the same bytes; nonce reuse would leak plaintext via XOR.
	again, err := c.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, sealed, again)
}

func TestNewAESGCMCipherKeyLengths(t *testing.T) {
	for _, n := range []int{16, 24, 32} {
		_, err := NewAESGCMCipher(bytes.Repeat([]byte("k"), n))
		require.NoError(t, err, "key length %d must be accepted", n)
	}
	for _, n := range []int{0, 15, 17, 31, 33, 64} {
		key := bytes.Repeat([]byte("k"), n)
		_, err := NewAESGCMCipher(key)
		require.Error(t, err, "key length %d must be rejected", n)
		assert.Contains(t, err.Error(), "16, 24 or 32")
		if n > 0 {
			assert.NotContains(t, err.Error(), string(key), "the error must not echo the key")
		}
	}
}

func TestAESGCMCipherDecryptWrongKey(t *testing.T) {
	a := testCipher(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	b := testCipher(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	sealed, err := a.Encrypt([]byte(`{"token":"s3cr3t"}`))
	require.NoError(t, err)

	_, err = b.Decrypt(sealed)
	require.Error(t, err, "a wrong key must be an error, not a panic")
	assert.NotContains(t, err.Error(), "s3cr3t")
	assert.NotContains(t, err.Error(), base64.StdEncoding.EncodeToString(sealed))
}

func TestAESGCMCipherDecryptTruncated(t *testing.T) {
	c := testCipher(t, testConfigKey)
	_, err := c.Decrypt([]byte("short"))
	require.Error(t, err)
}

func TestConfigEnvelopeRoundTrip(t *testing.T) {
	ct := []byte{1, 2, 3, 4}
	raw, err := encodeConfigEnvelope(ct)
	require.NoError(t, err)

	got, encrypted, err := parseConfigEnvelope(raw)
	require.NoError(t, err)
	require.True(t, encrypted)
	assert.Equal(t, ct, got)
}

func TestParseConfigEnvelopePlaintext(t *testing.T) {
	for _, raw := range []string{
		`{}`, `{"url":"u"}`, `[]`, `null`, `"x"`, ``,
		// A generic field named "encrypted" must not look like our
		// namespaced envelope.
		`{"encrypted":"gpg"}`, `{"encrypted":true}`, `{"sorobeacon_config":""}`,
	} {
		_, encrypted, err := parseConfigEnvelope([]byte(raw))
		require.NoError(t, err, raw)
		assert.False(t, encrypted, raw)
	}
}

func TestParseConfigEnvelopeUnknownVersion(t *testing.T) {
	_, _, err := parseConfigEnvelope([]byte(`{"sorobeacon_config":"v9:AAAA"}`))
	assert.ErrorContains(t, err, "unsupported")
}

// --- Postgres-backed tests (skip without TEST_DATABASE_URL) ---

func rawChannelConfig(t *testing.T, st *Postgres, id int64) []byte {
	t.Helper()
	var raw []byte
	require.NoError(t, st.pool.QueryRow(context.Background(),
		`SELECT config FROM channels WHERE id = $1`, id).Scan(&raw))
	return raw
}

func TestChannelConfigNoKeyStaysPlaintext(t *testing.T) {
	st := testStore(t) // no cipher configured
	ctx := context.Background()

	c := &Channel{Name: "plain", Type: "webhook", Config: json.RawMessage(`{"token":"s3cr3t"}`), Enabled: true}
	require.NoError(t, st.CreateChannel(ctx, c))

	raw := rawChannelConfig(t, st, c.ID)
	assert.Contains(t, string(raw), "s3cr3t", "no key must preserve the old plaintext behaviour")
	assert.NotContains(t, string(raw), `"sorobeacon_config"`)

	got, err := st.GetChannel(ctx, c.ID)
	require.NoError(t, err)
	assert.JSONEq(t, `{"token":"s3cr3t"}`, string(got.Config))
}

func TestChannelConfigEncryptedAtRest(t *testing.T) {
	st := testStore(t).WithConfigCipher(testCipher(t, testConfigKey))
	ctx := context.Background()

	const secretURL = "https://hooks.example/T000/B000/s3cr3t-path"
	const secretToken = "s3cr3t-token"
	cfg := json.RawMessage(`{"url":"` + secretURL + `","token":"` + secretToken + `"}`)
	c := &Channel{Name: "ops", Type: "webhook", Config: cfg, Enabled: true}
	require.NoError(t, st.CreateChannel(ctx, c))

	// The point of the feature: the raw column must contain no plaintext
	// secret, and must be recognisably an envelope.
	raw := rawChannelConfig(t, st, c.ID)
	assert.NotContains(t, string(raw), secretURL)
	assert.NotContains(t, string(raw), secretToken)
	assert.Contains(t, string(raw), `"sorobeacon_config"`)

	// Every read path decrypts transparently.
	got, err := st.GetChannel(ctx, c.ID)
	require.NoError(t, err)
	assert.JSONEq(t, string(cfg), string(got.Config))

	list, err := st.ListChannels(ctx, false)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.JSONEq(t, string(cfg), string(list[0].Config))

	page, err := st.ListChannelsPage(ctx, ListFilter{})
	require.NoError(t, err)
	require.Len(t, page, 1)
	assert.JSONEq(t, string(cfg), string(page[0].Config))

	m := &Monitor{Name: "m", ContractIDs: []string{"C"}, Enabled: true}
	require.NoError(t, st.CreateMonitor(ctx, m))
	require.NoError(t, st.SetMonitorChannels(ctx, m.ID, []int64{c.ID}))
	attached, err := st.ListChannelsForMonitor(ctx, m.ID)
	require.NoError(t, err)
	require.Len(t, attached, 1)
	assert.JSONEq(t, string(cfg), string(attached[0].Config))

	// Update re-encrypts: the rotated secret is not in the raw row either.
	c.Config = json.RawMessage(`{"url":"` + secretURL + `","token":"rotated"}`)
	require.NoError(t, st.UpdateChannel(ctx, c))
	assert.NotContains(t, string(rawChannelConfig(t, st, c.ID)), "rotated")
	got, err = st.GetChannel(ctx, c.ID)
	require.NoError(t, err)
	assert.JSONEq(t, `{"url":"`+secretURL+`","token":"rotated"}`, string(got.Config))
}

func TestChannelConfigLegacyPlaintextStaysReadableThenReencrypts(t *testing.T) {
	st := testStore(t) // plaintext row written before a key existed
	ctx := context.Background()

	const secret = "legacy-s3cr3t-token"
	legacyConfig := json.RawMessage(`{"token":"` + secret + `"}`)
	c := &Channel{Name: "legacy", Type: "webhook", Config: legacyConfig, Enabled: true}
	require.NoError(t, st.CreateChannel(ctx, c))
	assert.Contains(t, string(rawChannelConfig(t, st, c.ID)), secret)

	// A key is turned on for an existing deployment. The legacy row must
	// still read — an upgrade must never brick a running instance.
	st.WithConfigCipher(testCipher(t, testConfigKey))

	got, err := st.GetChannel(ctx, c.ID)
	require.NoError(t, err)
	assert.JSONEq(t, string(legacyConfig), string(got.Config))

	list, err := st.ListChannels(ctx, false)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.JSONEq(t, string(legacyConfig), string(list[0].Config))

	// It is re-encrypted lazily on the next write.
	c.Name = "legacy-renamed"
	require.NoError(t, st.UpdateChannel(ctx, c))
	raw := rawChannelConfig(t, st, c.ID)
	assert.NotContains(t, string(raw), secret)
	assert.Contains(t, string(raw), `"sorobeacon_config"`)
}

func TestChannelConfigDecryptFailureNamesChannel(t *testing.T) {
	st := testStore(t).WithConfigCipher(testCipher(t, testConfigKey))
	ctx := context.Background()

	c := &Channel{Name: "pager", Type: "webhook", Config: json.RawMessage(`{"token":"s3cr3t"}`), Enabled: true}
	require.NoError(t, st.CreateChannel(ctx, c))
	rawBefore := string(rawChannelConfig(t, st, c.ID))

	// Rotating the key without re-encrypting makes the stored row
	// undecryptable. That must be a clear error naming the channel — never
	// a panic, and never an echo of the ciphertext or key material.
	st.WithConfigCipher(testCipher(t, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"))

	_, err := st.GetChannel(ctx, c.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pager")
	assert.Contains(t, err.Error(), "decrypt config")
	assert.NotContains(t, err.Error(), "s3cr3t")
	assert.NotContains(t, err.Error(), rawBefore)

	// Listing must report the same failure rather than returning the
	// envelope as if it were plaintext config.
	_, err = st.ListChannels(ctx, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pager")
}
