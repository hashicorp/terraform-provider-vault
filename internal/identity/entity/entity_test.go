package entity

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"testing"

	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

type testFindAliasHandler struct {
	requests      int
	retryStatus   int
	wantErrOnList bool
	wantErrOnRead bool
	entities      []*Entity
}

func (t *testFindAliasHandler) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		t.requests++

		wantPath := "/v1" + RootEntityIDPath
		pathRE := regexp.MustCompile(fmt.Sprintf(`^%s/(.+)`, wantPath))
		path := req.URL.Path
		values := req.URL.Query()

		if req.Method != http.MethodGet {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var data map[string]interface{}
		if path == wantPath && values.Get("list") == "true" {
			if t.wantErrOnList {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			var ids []interface{}
			for _, e := range t.entities {
				ids = append(ids, e.ID)
			}
			data = map[string]interface{}{
				"keys": ids,
			}
		} else {
			if t.wantErrOnRead {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			match := pathRE.FindStringSubmatch(path)
			if len(match) > 1 {
				id := match[1]
				for _, e := range t.entities {
					if e.ID == id {
						b, err := json.Marshal(e)
						if err != nil {
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
						if err := json.Unmarshal(b, &data); err != nil {
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
					}
				}

			}
		}

		m, err := json.Marshal(
			&api.Secret{
				Data: data,
			},
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(m)
	}
}

func TestFindAliases(t *testing.T) {
	t.Parallel()

	aliasBob := &Alias{
		Name:          "bob",
		MountAccessor: "CC417368-0C63-407A-93AD-2D76A72F58E2",
	}

	aliasAlice := &Alias{
		Name:          "alice",
		MountAccessor: "CC417368-0C63-407A-93AD-2D76A72F58E3",
	}
	tests := []struct {
		name        string
		params      *FindAliasParams
		want        []*Alias
		findHandler *testFindAliasHandler
		wantErr     bool
	}{
		{
			name:   "empty",
			params: &FindAliasParams{},
			findHandler: &testFindAliasHandler{
				entities: []*Entity{},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name:   "all",
			params: &FindAliasParams{},
			findHandler: &testFindAliasHandler{
				entities: []*Entity{
					{
						ID: "C6D3410E-86AF-4A10-9282-4B1E9773932A",
						Aliases: []*Alias{
							aliasBob,
						},
					},
					{
						ID: "C6D3410E-86AF-4A10-9282-4B1E9773932B",
						Aliases: []*Alias{
							aliasAlice,
						},
					},
				},
			},
			want: []*Alias{
				aliasBob,
				aliasAlice,
			},
			wantErr: false,
		},
		{
			name: "name-only",
			params: &FindAliasParams{
				Name: aliasBob.Name,
			},
			findHandler: &testFindAliasHandler{
				entities: []*Entity{
					{
						ID: "C6D3410E-86AF-4A10-9282-4B1E9773932A",
						Aliases: []*Alias{
							aliasBob,
						},
					},
					{
						ID: "C6D3410E-86AF-4A10-9282-4B1E9773932B",
						Aliases: []*Alias{
							aliasAlice,
						},
					},
				},
			},
			want: []*Alias{
				aliasBob,
			},
			wantErr: false,
		},
		{
			name: "name-and-mount-accessor",
			params: &FindAliasParams{
				Name:          aliasBob.Name,
				MountAccessor: aliasBob.MountAccessor,
			},
			findHandler: &testFindAliasHandler{
				entities: []*Entity{
					{
						ID: "C6D3410E-86AF-4A10-9282-4B1E9773932A",
						Aliases: []*Alias{
							aliasAlice,
							{
								Name:          aliasBob.Name,
								MountAccessor: aliasAlice.MountAccessor,
							},
						},
					},
					{
						ID: "C6D3410E-86AF-4A10-9282-4B1E9773932B",
						Aliases: []*Alias{
							aliasBob,
						},
					},
				},
			},
			want: []*Alias{
				aliasBob,
			},
			wantErr: false,
		},
		{
			name: "mount-accessor-mismatch",
			params: &FindAliasParams{
				Name:          aliasBob.Name,
				MountAccessor: aliasAlice.MountAccessor,
			},
			findHandler: &testFindAliasHandler{
				entities: []*Entity{
					{
						ID: "C6D3410E-86AF-4A10-9282-4B1E9773932A",
						Aliases: []*Alias{
							aliasAlice,
						},
					},
					{
						ID: "C6D3410E-86AF-4A10-9282-4B1E9773932B",
						Aliases: []*Alias{
							aliasBob,
						},
					},
				},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "error-on-list",
			params: &FindAliasParams{
				Name:          aliasAlice.Name,
				MountAccessor: aliasBob.MountAccessor,
			},
			findHandler: &testFindAliasHandler{
				wantErrOnList: true,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name:   "error-on-read",
			params: &FindAliasParams{},
			findHandler: &testFindAliasHandler{
				entities: []*Entity{
					{
						ID: "C6D3410E-86AF-4A10-9282-4B1E9773932A",
						Aliases: []*Alias{
							aliasAlice,
						},
					},
				},
				wantErrOnRead: true,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.findHandler

			config, ln := testutil.TestHTTPServer(t, r.handler())
			defer ln.Close()

			config.Address = fmt.Sprintf("http://%s", ln.Addr())
			c, err := api.NewClient(config)
			if err != nil {
				t.Fatal(err)
			}

			got, err := FindAliases(c, tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindAliases() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindAliases() got = %v, want %v", got, tt.want)
			}
		})
	}
}
