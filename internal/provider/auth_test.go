// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

type authLoginTest struct {
	name               string
	authLogin          AuthLogin
	handler            *testLoginHandler
	want               *api.Secret
	expectReqCount     int
	skipCheckReqParams bool
	expectReqParams    []map[string]interface{}
	expectReqPaths     []string
	wantErr            bool
	expectErr          error
	skipFunc           func(t *testing.T)
}

type testLoginHandler struct {
	requestCount  int
	paths         []string
	params        []map[string]interface{}
	excludeParams []string
	handlerFunc   func(t *testLoginHandler, w http.ResponseWriter, req *http.Request)
}

func (t *testLoginHandler) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		t.requestCount++

		t.paths = append(t.paths, req.URL.Path)

		if req.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		b, err := ioutil.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var params map[string]interface{}
		if err := json.Unmarshal(b, &params); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		for _, p := range t.excludeParams {
			delete(params, p)
		}

		t.params = append(t.params, params)

		t.handlerFunc(t, w, req)
	}
}

func testAuthLogin(t *testing.T, tt authLoginTest) {
	t.Helper()

	if tt.skipFunc != nil {
		tt.skipFunc(t)
	}

	config, ln := testutil.TestHTTPServer(t, tt.handler.handler())
	defer ln.Close()

	config.Address = fmt.Sprintf("http://%s", ln.Addr())
	c, err := api.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}

	got, err := tt.authLogin.Login(c)
	if (err != nil) != tt.wantErr {
		t.Errorf("Login() error = %v, wantErr %v", err, tt.wantErr)
		return
	}

	if err != nil && tt.expectErr != nil {
		if !reflect.DeepEqual(tt.expectErr, err) {
			t.Errorf("Login() expected error %#v, actual %#v", tt.expectErr, err)
		}
	}

	if tt.expectReqCount != tt.handler.requestCount {
		t.Errorf("Login() expected %d requests, actual %d", tt.expectReqCount, tt.handler.requestCount)
	}

	if !reflect.DeepEqual(tt.expectReqPaths, tt.handler.paths) {
		t.Errorf("Login() request paths do not match expected %#v, actual %#v", tt.expectReqPaths,
			tt.handler.paths)
	}

	if !tt.skipCheckReqParams && !reflect.DeepEqual(tt.expectReqParams, tt.handler.params) {
		t.Errorf("Login() request params do not match expected %#v, actual %#v", tt.expectReqParams,
			tt.handler.params)
	}

	if !reflect.DeepEqual(got, tt.want) {
		t.Errorf("Login() got = %#v, want %#v", got, tt.want)
	}
}
