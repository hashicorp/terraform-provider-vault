// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package os

import (
	"strings"
	"testing"
)

// hostIDResult holds the parsed components of a host ID
type hostIDResult struct {
	mount string
	name  string
}

// accountIDResult holds the parsed components of an account ID
type accountIDResult struct {
	mount string
	host  string
	name  string
}

func TestParseHostID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		id      string
		want    hostIDResult
		wantErr bool
	}{
		{
			name: "valid simple path",
			id:   "os/hosts/web-server",
			want: hostIDResult{mount: "os", name: "web-server"},
		},
		{
			name: "valid with hyphens",
			id:   "os-manual/hosts/test-host-01",
			want: hostIDResult{mount: "os-manual", name: "test-host-01"},
		},
		{
			name: "valid with underscores",
			id:   "os_prod/hosts/db_server_01",
			want: hostIDResult{mount: "os_prod", name: "db_server_01"},
		},
		{
			name: "valid with numbers",
			id:   "os123/hosts/host456",
			want: hostIDResult{mount: "os123", name: "host456"},
		},
		{
			name: "valid with dots",
			id:   "os.prod/hosts/server.example.com",
			want: hostIDResult{mount: "os.prod", name: "server.example.com"},
		},
		{
			name:    "missing hosts segment",
			id:      "os/web-server",
			wantErr: true,
		},
		{
			name:    "wrong segment name",
			id:      "os/host/web-server",
			wantErr: true,
		},
		{
			name:    "too many segments",
			id:      "os/hosts/web-server/extra",
			wantErr: true,
		},
		{
			name:    "empty string",
			id:      "",
			wantErr: true,
		},
		{
			name:    "only mount",
			id:      "os",
			wantErr: true,
		},
		{
			name:    "trailing slash",
			id:      "os/hosts/web-server/",
			wantErr: true,
		},
		{
			name:    "leading slash",
			id:      "/os/hosts/web-server",
			wantErr: true,
		},
		{
			name:    "double slash",
			id:      "os//hosts/web-server",
			wantErr: true,
		},
		{
			name:    "account path (should fail)",
			id:      "os/hosts/web-server/accounts/admin",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotMount, gotName, err := parseHostID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHostID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				got := hostIDResult{mount: gotMount, name: gotName}
				if got != tt.want {
					t.Errorf("parseHostID() = %+v, want %+v", got, tt.want)
				}
			}
		})
	}
}

func TestParseAccountID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		id      string
		want    accountIDResult
		wantErr bool
	}{
		{
			name: "valid simple path",
			id:   "os/hosts/web-server/accounts/admin",
			want: accountIDResult{mount: "os", host: "web-server", name: "admin"},
		},
		{
			name: "valid with hyphens",
			id:   "os-manual/hosts/test-host-01/accounts/admin-account",
			want: accountIDResult{mount: "os-manual", host: "test-host-01", name: "admin-account"},
		},
		{
			name: "valid with underscores",
			id:   "os_prod/hosts/db_server/accounts/db_admin",
			want: accountIDResult{mount: "os_prod", host: "db_server", name: "db_admin"},
		},
		{
			name: "valid with numbers",
			id:   "os123/hosts/host456/accounts/user789",
			want: accountIDResult{mount: "os123", host: "host456", name: "user789"},
		},
		{
			name: "valid with dots",
			id:   "os.prod/hosts/server.example.com/accounts/admin.user",
			want: accountIDResult{mount: "os.prod", host: "server.example.com", name: "admin.user"},
		},
		{
			name:    "missing accounts segment",
			id:      "os/hosts/web-server/admin",
			wantErr: true,
		},
		{
			name:    "wrong segment name",
			id:      "os/hosts/web-server/account/admin",
			wantErr: true,
		},
		{
			name:    "too many segments",
			id:      "os/hosts/web-server/accounts/admin/extra",
			wantErr: true,
		},
		{
			name:    "too few segments",
			id:      "os/hosts/web-server",
			wantErr: true,
		},
		{
			name:    "empty string",
			id:      "",
			wantErr: true,
		},
		{
			name:    "only mount",
			id:      "os",
			wantErr: true,
		},
		{
			name:    "trailing slash",
			id:      "os/hosts/web-server/accounts/admin/",
			wantErr: true,
		},
		{
			name:    "leading slash",
			id:      "/os/hosts/web-server/accounts/admin",
			wantErr: true,
		},
		{
			name:    "double slash",
			id:      "os//hosts/web-server/accounts/admin",
			wantErr: true,
		},
		{
			name:    "empty mount",
			id:      "/hosts/web-server/accounts/admin",
			wantErr: true,
		},
		{
			name:    "empty host",
			id:      "os/hosts//accounts/admin",
			wantErr: true,
		},
		{
			name:    "empty account name",
			id:      "os/hosts/web-server/accounts/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotMount, gotHost, gotName, err := parseAccountID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAccountID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				got := accountIDResult{mount: gotMount, host: gotHost, name: gotName}
				if got != tt.want {
					t.Errorf("parseAccountID() = %+v, want %+v", got, tt.want)
				}
			}
		})
	}
}

// TestHostIDRegexEdgeCases tests edge cases for the hostIDRe regex
func TestHostIDRegexEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"valid with hyphens and dots", "os-prod_v1.2/hosts/server-01.example.com", false},
		{"single char mount", "o/hosts/server", false},
		{"single char host", "os/hosts/s", false},
		{"very long valid name", "os/hosts/" + strings.Repeat("a", 200), false},
		{"leading hyphen not allowed", "-os/hosts/server", true},
		{"trailing hyphen not allowed", "os/hosts/server-", true},
		{"leading dot not allowed", ".os/hosts/server", true},
		{"trailing dot not allowed", "os/hosts/server.", true},
		{"only hyphen not allowed", "os/hosts/-", true},
		{"only dot not allowed", "os/hosts/.", true},
		{"special chars not allowed", "os@prod/hosts/server", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := parseHostID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHostID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestAccountIDRegexEdgeCases tests edge cases for the accountIDRe regex
func TestAccountIDRegexEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"valid with hyphens, underscores, and dots", "os-prod_v1.2/hosts/server-01_prod.example.com/accounts/admin-user_01.test", false},
		{"single char names", "o/hosts/s/accounts/a", false},
		{"very long valid names", "os/hosts/" + strings.Repeat("a", 100) + "/accounts/" + strings.Repeat("b", 100), false},
		{"leading hyphen not allowed in mount", "-os/hosts/server/accounts/admin", true},
		{"trailing hyphen not allowed in host", "os/hosts/server-/accounts/admin", true},
		{"leading dot not allowed in account", "os/hosts/server/accounts/.admin", true},
		{"trailing dot not allowed in mount", "os./hosts/server/accounts/admin", true},
		{"special chars not allowed", "os@prod/hosts/server/accounts/admin", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, _, err := parseAccountID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAccountID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
