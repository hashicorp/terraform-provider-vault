// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func TestAuthLoginTokenFile_Init(t *testing.T) {
	tests := []authLoginInitTest{
		{
			name:      "basic",
			authField: consts.FieldAuthLoginTokenFile,
			raw: map[string]interface{}{
				consts.FieldAuthLoginTokenFile: []interface{}{
					map[string]interface{}{
						consts.FieldFilename: "vault-token",
					},
				},
			},
			expectParams: map[string]interface{}{
				consts.FieldNamespace:        "",
				consts.FieldUseRootNamespace: false,
				consts.FieldFilename:         "vault-token",
			},
			wantErr: false,
		},
		{
			name:      "basic-from-env",
			authField: consts.FieldAuthLoginTokenFile,
			raw: map[string]interface{}{
				consts.FieldAuthLoginTokenFile: []interface{}{
					map[string]interface{}{},
				},
			},
			envVars: map[string]string{
				consts.EnvVarTokenFilename: "/tmp/vault-token",
			},
			expectParams: map[string]interface{}{
				consts.FieldFilename: "/tmp/vault-token",
			},
			wantErr: false,
		},
		{
			name:         "error-missing-resource",
			authField:    consts.FieldAuthLoginTokenFile,
			expectParams: nil,
			wantErr:      true,
			expectErr:    fmt.Errorf("resource data missing field %q", consts.FieldAuthLoginTokenFile),
		},
		{
			name:      "error-missing-required",
			authField: consts.FieldAuthLoginTokenFile,
			raw: map[string]interface{}{
				consts.FieldAuthLoginTokenFile: []interface{}{
					map[string]interface{}{},
				},
			},
			expectParams: nil,
			wantErr:      true,
			expectErr: fmt.Errorf("required fields are unset: %v", []string{
				consts.FieldFilename,
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := map[string]*schema.Schema{
				tt.authField: GetTokenFileSchema(tt.authField),
			}
			assertAuthLoginInit(t, tt, s, &AuthLoginTokenFile{})
		})
	}
}

func TestAuthLoginTokenFile_Login(t *testing.T) {
	handlerFunc := func(t *testLoginHandler, w http.ResponseWriter, req *http.Request) {
		m, err := json.Marshal(
			&api.Secret{
				Auth: &api.SecretAuth{},
			},
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if _, err := w.Write(m); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	tempDir := t.TempDir()
	tests := []authLoginTest{
		{
			name: "basic",
			authLogin: &AuthLoginTokenFile{
				AuthLoginCommon{
					authField: "baz",
					mount:     consts.MountTypeNone,
					params: map[string]interface{}{
						consts.FieldFilename: path.Join(tempDir, "basic"),
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount: 1,
			expectReqPaths: []string{
				"/v1/auth/token/lookup-self",
			},
			expectReqParams: nil,
			want: &api.Secret{
				Auth: &api.SecretAuth{
					ClientToken: "qux",
				},
			},
			preLoginFunc: func(t *testing.T) {
				t.Helper()

				filename := path.Join(tempDir, "basic")
				t.Cleanup(func() {
					if err := os.Remove(filename); err != nil {
						t.Error(err)
					}
				})
				if err := os.WriteFile(filename, []byte("qux\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: false,
		},
		{
			name: "error-vault-token-set",
			authLogin: &AuthLoginTokenFile{
				AuthLoginCommon{
					authField: "baz",
					mount:     consts.MountTypeNone,
					params: map[string]interface{}{
						consts.FieldFilename: path.Join(tempDir, "basic"),
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			preLoginFunc: func(t *testing.T) {
				t.Helper()

				filename := path.Join(tempDir, "basic")
				t.Cleanup(func() {
					if err := os.Remove(filename); err != nil {
						t.Error(err)
					}
				})
				if err := os.WriteFile(filename, []byte("qux\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			token:     "foo",
			wantErr:   true,
			expectErr: errors.New("vault login client has a token set"),
		},
		{
			name: "error-invalid-file-mode",
			authLogin: &AuthLoginTokenFile{
				AuthLoginCommon{
					authField: "baz",
					mount:     consts.MountTypeNone,
					params: map[string]interface{}{
						consts.FieldFilename: path.Join(tempDir, "error-invalid-file-mode"),
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount: 0,
			preLoginFunc: func(t *testing.T) {
				t.Helper()

				filename := path.Join(tempDir, "error-invalid-file-mode")
				t.Cleanup(func() {
					if err := os.Remove(filename); err != nil {
						t.Error(err)
					}
				})
				if err := os.WriteFile(filename, []byte("qux\n"), 0o660); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: true,
		},
		{
			name: "error-not-a-file",
			authLogin: &AuthLoginTokenFile{
				AuthLoginCommon{
					authField: "baz",
					mount:     consts.MountTypeNone,
					params: map[string]interface{}{
						consts.FieldFilename: path.Join(tempDir, "error-not-a-file"),
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount: 0,
			preLoginFunc: func(t *testing.T) {
				t.Helper()

				filename := path.Join(tempDir, "error-not-a-file")
				t.Cleanup(func() {
					if err := os.RemoveAll(filename); err != nil {
						t.Error(err)
					}
				})
				if err := os.Mkdir(filename, 0o770); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: true,
		},
		{
			name: "error-uninitialized",
			authLogin: &AuthLoginTokenFile{
				AuthLoginCommon{
					initialized: false,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			want:      nil,
			wantErr:   true,
			expectErr: authLoginInitCheckError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testAuthLogin(t, tt)
		})
	}
}

func TestAuthLoginTokenFile_readTokenFile(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name     string
		mode     os.FileMode
		asDir    bool
		contents []byte
		want     string
		wantErr  bool
	}{
		{
			name:     "basic",
			contents: []byte("foo"),
			want:     "foo",
			mode:     0o600,
			wantErr:  false,
		},
		{
			name:     "invalid-empty",
			contents: make([]byte, 0),
			mode:     0o600,
			wantErr:  true,
		},
		{
			name:     "invalid-empty-with-newline",
			contents: []byte("\n"),
			mode:     0o600,
			wantErr:  true,
		},
		{
			name:     "invalid-file-perms-0640",
			contents: []byte("foo"),
			mode:     0o640,
			wantErr:  true,
		},
		{
			name:     "invalid-file-perms-0644",
			contents: []byte("foo"),
			mode:     0o644,
			wantErr:  true,
		},
		{
			name:     "invalid-file-perms-0604",
			contents: []byte("foo"),
			mode:     0o604,
			wantErr:  true,
		},
		{
			name:     "invalid-multi-line",
			contents: []byte("foo\nbaz"),
			mode:     0o600,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var filename string
			if tt.asDir {
				dirname, err := os.MkdirTemp(tempDir, "test-")
				if err != nil {
					t.Fatal(err)
				}
				filename = dirname
			} else {
				fh, err := os.CreateTemp(tempDir, "test-")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := fh.Write(tt.contents); err != nil {
					t.Fatal(err)
				}
				if err := fh.Close(); err != nil {
					t.Fatal(err)
				}

				filename = fh.Name()
				if err := os.Chmod(fh.Name(), tt.mode); err != nil {
					t.Fatal(err)
				}
			}

			t.Cleanup(func() {
				if err := os.RemoveAll(filename); err != nil {
					t.Fatal(err)
				}
			})

			l := &AuthLoginTokenFile{
				AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldFilename: filename,
					},
				},
			}

			got, err := l.readTokenFile()
			if (err != nil) != tt.wantErr {
				t.Errorf("readTokenFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("readTokenFile() got = %v, want %v", got, tt.want)
			}
		})
	}
}
