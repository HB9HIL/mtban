package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// testCfg returns a minimal valid config map pointing at the given URL.
func testCfg(url string) map[string]string {
	return map[string]string{"url": url, "username": "u", "password": "p"}
}

// staticServer returns a test server that always responds with resp encoded as JSON.
func staticServer(t *testing.T, resp any) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv, srv.Client()
}

// writeTempConfig writes content to a temp file and returns its path.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "mtban*.conf")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(content) //nolint:errcheck
	f.Close()
	return f.Name()
}

// --- parseArgs ---

func TestParseArgs(t *testing.T) {
	t.Run("minimal ban", func(t *testing.T) {
		opts, err := parseArgs([]string{"ban", "1.2.3.4"})
		if err != nil {
			t.Fatal(err)
		}
		if opts.Action != "ban" || opts.IP != "1.2.3.4" {
			t.Errorf("unexpected opts: %+v", opts)
		}
		if opts.List != "blocked" {
			t.Errorf("default list = %q, want blocked", opts.List)
		}
		if opts.Comment != "mtban" {
			t.Errorf("default comment = %q, want mtban", opts.Comment)
		}
	})

	t.Run("minimal unban with IPv6", func(t *testing.T) {
		opts, err := parseArgs([]string{"unban", "2001:db8::1"})
		if err != nil {
			t.Fatal(err)
		}
		if opts.Action != "unban" || opts.IP != "2001:db8::1" {
			t.Errorf("unexpected opts: %+v", opts)
		}
	})

	t.Run("all flags", func(t *testing.T) {
		opts, err := parseArgs([]string{
			"--list", "custom",
			"--timeout", "30s",
			"--comment", "test",
			"--config", "/tmp/x.conf",
			"ban", "1.2.3.4",
		})
		if err != nil {
			t.Fatal(err)
		}
		if opts.List != "custom" {
			t.Errorf("list = %q, want custom", opts.List)
		}
		if opts.Timeout != "30s" {
			t.Errorf("timeout = %q, want 30s", opts.Timeout)
		}
		if opts.Comment != "test" {
			t.Errorf("comment = %q, want test", opts.Comment)
		}
		if opts.Config != "/tmp/x.conf" {
			t.Errorf("config = %q, want /tmp/x.conf", opts.Config)
		}
	})

	t.Run("inline flag value", func(t *testing.T) {
		opts, err := parseArgs([]string{"--list=custom", "ban", "1.2.3.4"})
		if err != nil {
			t.Fatal(err)
		}
		if opts.List != "custom" {
			t.Errorf("list = %q, want custom", opts.List)
		}
	})

	t.Run("CIDR as IP argument", func(t *testing.T) {
		opts, err := parseArgs([]string{"ban", "10.0.0.0/8"})
		if err != nil {
			t.Fatal(err)
		}
		if opts.IP != "10.0.0.0/8" {
			t.Errorf("IP = %q, want 10.0.0.0/8", opts.IP)
		}
	})

	errCases := []struct {
		name string
		args []string
	}{
		{"help long", []string{"--help"}},
		{"help short", []string{"-h"}},
		{"missing ip", []string{"ban"}},
		{"too many positionals", []string{"ban", "1.2.3.4", "extra"}},
		{"unknown action", []string{"kick", "1.2.3.4"}},
		{"unknown long flag", []string{"--unknown", "ban", "1.2.3.4"}},
		{"short flag", []string{"-x", "ban", "1.2.3.4"}},
		{"flag missing value", []string{"--list"}},
	}
	for _, tc := range errCases {
		t.Run("error: "+tc.name, func(t *testing.T) {
			if _, err := parseArgs(tc.args); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// --- loadConfig ---

func TestLoadConfig(t *testing.T) {
	t.Run("valid minimal", func(t *testing.T) {
		p := writeTempConfig(t, "url=http://router\nusername=u\npassword=p\n")
		cfg, err := loadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		if cfg["url"] != "http://router" {
			t.Errorf("url = %q", cfg["url"])
		}
	})

	t.Run("spaces around equals and comment lines", func(t *testing.T) {
		p := writeTempConfig(t, "# comment\n\nurl = http://router\nusername = u\npassword = p\n")
		cfg, err := loadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		if cfg["url"] != "http://router" {
			t.Errorf("url = %q", cfg["url"])
		}
	})

	t.Run("subnet options are parsed", func(t *testing.T) {
		p := writeTempConfig(t, "url=http://r\nusername=u\npassword=p\nban_v4_subnet=28\nban_v6_subnet=48\n")
		cfg, err := loadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		if cfg["ban_v4_subnet"] != "28" {
			t.Errorf("ban_v4_subnet = %q, want 28", cfg["ban_v4_subnet"])
		}
		if cfg["ban_v6_subnet"] != "48" {
			t.Errorf("ban_v6_subnet = %q, want 48", cfg["ban_v6_subnet"])
		}
	})

	t.Run("lines without equals sign are skipped", func(t *testing.T) {
		p := writeTempConfig(t, "url=http://r\nusername=u\npassword=p\ngarbage\n")
		_, err := loadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
	})

	for _, key := range []string{"url", "username", "password"} {
		key := key
		t.Run("missing required key: "+key, func(t *testing.T) {
			all := map[string]string{"url": "http://r", "username": "u", "password": "p"}
			delete(all, key)
			var sb strings.Builder
			for k, v := range all {
				sb.WriteString(k + "=" + v + "\n")
			}
			p := writeTempConfig(t, sb.String())
			if _, err := loadConfig(p); err == nil {
				t.Fatal("expected error for missing key:", key)
			}
		})
	}

	t.Run("file not found", func(t *testing.T) {
		if _, err := loadConfig("/nonexistent/path/mtban.conf"); err == nil {
			t.Fatal("expected error")
		}
	})
}

// --- addressListEndpoint ---

func TestAddressListEndpoint(t *testing.T) {
	tests := []struct{ ip, want string }{
		{"1.2.3.4", "ip/firewall/address-list"},
		{"1.2.3.0/28", "ip/firewall/address-list"},
		{"2001:db8::1", "ipv6/firewall/address-list"},
		{"2001:db8::/48", "ipv6/firewall/address-list"},
	}
	for _, tt := range tests {
		got := addressListEndpoint(tt.ip)
		if got != tt.want {
			t.Errorf("addressListEndpoint(%q) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

// --- applySubnetConfig ---

func TestApplySubnetConfig(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		cfg     map[string]string
		want    string
		wantErr bool
	}{
		// IPv4 — bare IPs with default config pass through unchanged
		{"v4 bare, no config", "1.2.3.4", nil, "1.2.3.4", false},
		{"v4 bare, explicit /32", "1.2.3.4", map[string]string{"ban_v4_subnet": "32"}, "1.2.3.4", false},

		// IPv4 — subnet expansion rounds host IP to network address
		{"v4 bare → /28", "123.123.123.123", map[string]string{"ban_v4_subnet": "28"}, "123.123.123.112/28", false},
		{"v4 bare → /24", "192.168.1.200", map[string]string{"ban_v4_subnet": "24"}, "192.168.1.0/24", false},
		{"v4 bare → /16", "10.20.30.40", map[string]string{"ban_v4_subnet": "16"}, "10.20.0.0/16", false},
		{"v4 /32 → /28", "1.2.3.4/32", map[string]string{"ban_v4_subnet": "28"}, "1.2.3.0/28", false},
		{"v4 /32 with default config", "1.2.3.4/32", nil, "1.2.3.4/32", false},

		// IPv4 — larger blocks (smaller prefix number) always pass through unchanged
		{"v4 /16 with config /28", "10.1.2.3/16", map[string]string{"ban_v4_subnet": "28"}, "10.1.0.0/16", false},
		{"v4 /28 == config /28", "123.123.123.112/28", map[string]string{"ban_v4_subnet": "28"}, "123.123.123.112/28", false},
		{"v4 /8 with config /16", "10.0.0.0/8", map[string]string{"ban_v4_subnet": "16"}, "10.0.0.0/8", false},

		// Config value with leading slash is accepted
		{"v4 slash-prefix notation", "1.2.3.4", map[string]string{"ban_v4_subnet": "/28"}, "1.2.3.0/28", false},

		// IPv6 — bare addresses with default config pass through unchanged
		{"v6 bare, no config", "2001:db8::1", nil, "2001:db8::1", false},
		{"v6 bare, explicit /128", "2001:db8::1", map[string]string{"ban_v6_subnet": "128"}, "2001:db8::1", false},

		// IPv6 — subnet expansion
		{"v6 bare → /48", "2001:db8::1", map[string]string{"ban_v6_subnet": "48"}, "2001:db8::/48", false},
		{"v6 /128 → /48", "2001:db8::1/128", map[string]string{"ban_v6_subnet": "48"}, "2001:db8::/48", false},
		{"v6 /128 with default config", "2001:db8::1/128", nil, "2001:db8::1/128", false},

		// IPv6 — larger blocks pass through
		{"v6 /32 with config /48", "2001:db8::/32", map[string]string{"ban_v6_subnet": "48"}, "2001:db8::/32", false},

		// Invalid config values produce errors
		{"invalid: non-numeric", "1.2.3.4", map[string]string{"ban_v4_subnet": "abc"}, "", true},
		{"invalid: v4 prefix > 32", "1.2.3.4", map[string]string{"ban_v4_subnet": "33"}, "", true},
		{"invalid: negative prefix", "1.2.3.4", map[string]string{"ban_v4_subnet": "-1"}, "", true},
		{"invalid: v6 prefix > 128", "2001:db8::1", map[string]string{"ban_v6_subnet": "129"}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := applySubnetConfig(tt.ip, tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("applySubnetConfig(%q) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("applySubnetConfig(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

// --- findID ---

func TestFindID(t *testing.T) {
	t.Run("found: bare IP stored as bare", func(t *testing.T) {
		entries := []map[string]any{{".id": "*1", "list": "blocked", "address": "1.2.3.4"}}
		srv, client := staticServer(t, entries)
		id, err := findID(client, testCfg(srv.URL), "blocked", "1.2.3.4")
		if err != nil {
			t.Fatal(err)
		}
		if id != "*1" {
			t.Errorf("id = %q, want *1", id)
		}
	})

	t.Run("found: bare IP stored as /32 CIDR", func(t *testing.T) {
		entries := []map[string]any{{".id": "*2", "list": "blocked", "address": "1.2.3.4/32"}}
		srv, client := staticServer(t, entries)
		id, err := findID(client, testCfg(srv.URL), "blocked", "1.2.3.4")
		if err != nil {
			t.Fatal(err)
		}
		if id != "*2" {
			t.Errorf("id = %q, want *2", id)
		}
	})

	t.Run("found: CIDR input matches CIDR entry", func(t *testing.T) {
		entries := []map[string]any{{".id": "*3", "list": "blocked", "address": "1.2.3.0/28"}}
		srv, client := staticServer(t, entries)
		id, err := findID(client, testCfg(srv.URL), "blocked", "1.2.3.0/28")
		if err != nil {
			t.Fatal(err)
		}
		if id != "*3" {
			t.Errorf("id = %q, want *3", id)
		}
	})

	t.Run("found: IPv6 bare", func(t *testing.T) {
		entries := []map[string]any{{".id": "*4", "list": "blocked", "address": "2001:db8::1"}}
		srv, client := staticServer(t, entries)
		id, err := findID(client, testCfg(srv.URL), "blocked", "2001:db8::1")
		if err != nil {
			t.Fatal(err)
		}
		if id != "*4" {
			t.Errorf("id = %q, want *4", id)
		}
	})

	t.Run("found: IPv6 CIDR", func(t *testing.T) {
		entries := []map[string]any{{".id": "*5", "list": "blocked", "address": "2001:db8::/48"}}
		srv, client := staticServer(t, entries)
		id, err := findID(client, testCfg(srv.URL), "blocked", "2001:db8::/48")
		if err != nil {
			t.Fatal(err)
		}
		if id != "*5" {
			t.Errorf("id = %q, want *5", id)
		}
	})

	t.Run("not found: different IP", func(t *testing.T) {
		entries := []map[string]any{{".id": "*1", "list": "blocked", "address": "5.5.5.5"}}
		srv, client := staticServer(t, entries)
		id, err := findID(client, testCfg(srv.URL), "blocked", "1.2.3.4")
		if err != nil {
			t.Fatal(err)
		}
		if id != "" {
			t.Errorf("expected empty id, got %q", id)
		}
	})

	t.Run("not found: empty list", func(t *testing.T) {
		srv, client := staticServer(t, []map[string]any{})
		id, err := findID(client, testCfg(srv.URL), "blocked", "1.2.3.4")
		if err != nil {
			t.Fatal(err)
		}
		if id != "" {
			t.Errorf("expected empty id, got %q", id)
		}
	})

	t.Run("uses IPv6 endpoint for IPv6 address", func(t *testing.T) {
		var gotPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]map[string]any{}) //nolint:errcheck
		}))
		t.Cleanup(srv.Close)
		findID(srv.Client(), testCfg(srv.URL), "blocked", "2001:db8::1") //nolint:errcheck
		if !strings.Contains(gotPath, "ipv6") {
			t.Errorf("path %q should contain 'ipv6'", gotPath)
		}
	})

	t.Run("api error propagates", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}))
		t.Cleanup(srv.Close)
		if _, err := findID(srv.Client(), testCfg(srv.URL), "blocked", "1.2.3.4"); err == nil {
			t.Fatal("expected error")
		}
	})
}

// --- ban ---

func TestBan(t *testing.T) {
	t.Run("new entry uses PUT", func(t *testing.T) {
		var gotMethod string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod = r.Method
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{".id": "*1"}) //nolint:errcheck
		}))
		t.Cleanup(srv.Close)

		opts := options{IP: "1.2.3.4", List: "blocked", Comment: "mtban"}
		if err := ban(srv.Client(), testCfg(srv.URL), opts, ""); err != nil {
			t.Fatal(err)
		}
		if gotMethod != http.MethodPut {
			t.Errorf("method = %q, want PUT", gotMethod)
		}
	})

	t.Run("existing entry uses PATCH", func(t *testing.T) {
		var gotMethod string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod = r.Method
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{".id": "*1"}) //nolint:errcheck
		}))
		t.Cleanup(srv.Close)

		opts := options{IP: "1.2.3.4", List: "blocked", Comment: "mtban"}
		if err := ban(srv.Client(), testCfg(srv.URL), opts, "*1"); err != nil {
			t.Fatal(err)
		}
		if gotMethod != http.MethodPatch {
			t.Errorf("method = %q, want PATCH", gotMethod)
		}
	})

	t.Run("PUT body contains address, list, comment", func(t *testing.T) {
		var body map[string]string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{".id": "*1"}) //nolint:errcheck
		}))
		t.Cleanup(srv.Close)

		opts := options{IP: "1.2.3.4", List: "blocked", Comment: "mtban"}
		if err := ban(srv.Client(), testCfg(srv.URL), opts, ""); err != nil {
			t.Fatal(err)
		}
		if body["address"] != "1.2.3.4" {
			t.Errorf("address = %q, want 1.2.3.4", body["address"])
		}
		if body["list"] != "blocked" {
			t.Errorf("list = %q, want blocked", body["list"])
		}
		if body["comment"] != "mtban" {
			t.Errorf("comment = %q, want mtban", body["comment"])
		}
	})

	t.Run("timeout included in PUT when set", func(t *testing.T) {
		var body map[string]string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{".id": "*1"}) //nolint:errcheck
		}))
		t.Cleanup(srv.Close)

		opts := options{IP: "1.2.3.4", List: "blocked", Comment: "mtban", Timeout: "1d"}
		if err := ban(srv.Client(), testCfg(srv.URL), opts, ""); err != nil {
			t.Fatal(err)
		}
		if body["timeout"] != "1d" {
			t.Errorf("timeout = %q, want 1d", body["timeout"])
		}
	})

	t.Run("timeout omitted from PUT when not set", func(t *testing.T) {
		var body map[string]string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{".id": "*1"}) //nolint:errcheck
		}))
		t.Cleanup(srv.Close)

		opts := options{IP: "1.2.3.4", List: "blocked", Comment: "mtban"}
		if err := ban(srv.Client(), testCfg(srv.URL), opts, ""); err != nil {
			t.Fatal(err)
		}
		if _, ok := body["timeout"]; ok {
			t.Error("timeout should not be present when not set")
		}
	})

	t.Run("timeout included in PATCH when set", func(t *testing.T) {
		var body map[string]string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{".id": "*1"}) //nolint:errcheck
		}))
		t.Cleanup(srv.Close)

		opts := options{IP: "1.2.3.4", List: "blocked", Comment: "updated", Timeout: "2h"}
		if err := ban(srv.Client(), testCfg(srv.URL), opts, "*1"); err != nil {
			t.Fatal(err)
		}
		if body["timeout"] != "2h" {
			t.Errorf("timeout = %q, want 2h", body["timeout"])
		}
	})

	t.Run("timeout omitted from PATCH when not set", func(t *testing.T) {
		var body map[string]string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{".id": "*1"}) //nolint:errcheck
		}))
		t.Cleanup(srv.Close)

		opts := options{IP: "1.2.3.4", List: "blocked", Comment: "mtban"}
		if err := ban(srv.Client(), testCfg(srv.URL), opts, "*1"); err != nil {
			t.Fatal(err)
		}
		if _, ok := body["timeout"]; ok {
			t.Error("timeout should not be present in PATCH body when not set")
		}
	})

	t.Run("api error propagates", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "forbidden", http.StatusForbidden)
		}))
		t.Cleanup(srv.Close)

		opts := options{IP: "1.2.3.4", List: "blocked", Comment: "mtban"}
		if err := ban(srv.Client(), testCfg(srv.URL), opts, ""); err == nil {
			t.Fatal("expected error")
		}
	})
}

// --- unban ---

func TestUnban(t *testing.T) {
	t.Run("existing entry sends DELETE", func(t *testing.T) {
		var gotMethod string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod = r.Method
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(srv.Close)

		if err := unban(srv.Client(), testCfg(srv.URL), "1.2.3.4", "*1"); err != nil {
			t.Fatal(err)
		}
		if gotMethod != http.MethodDelete {
			t.Errorf("method = %q, want DELETE", gotMethod)
		}
	})

	t.Run("empty ID is a no-op", func(t *testing.T) {
		called := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		t.Cleanup(srv.Close)

		if err := unban(srv.Client(), testCfg(srv.URL), "1.2.3.4", ""); err != nil {
			t.Fatal(err)
		}
		if called {
			t.Error("no HTTP request should be made when ID is empty")
		}
	})

	t.Run("api error propagates", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)

		if err := unban(srv.Client(), testCfg(srv.URL), "1.2.3.4", "*1"); err == nil {
			t.Fatal("expected error")
		}
	})
}
