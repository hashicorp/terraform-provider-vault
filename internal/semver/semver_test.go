package semver

//func TestSemVerComparison(t *testing.T) {
//	client := testProvider.Meta().(*api.Client)
//
//	testCases := []struct {
//		name         string
//		minVersion   string
//		expected     bool
//		retryHandler *testRetryHandler
//	}{
//		{
//			"less-than",
//			"1.8.0",
//			true,
//		},
//		{
//			"greater-than",
//			"1.12.0",
//			false,
//		},
//		{
//			"equal",
//			"1.10.0",
//			true,
//		},
//	}

//config, ln := testHTTPServer(t, r.handler())
//defer ln.Close()
//
//config.Address = fmt.Sprintf("http://%s", ln.Addr())
//c, err := api.NewClient(config)
//if err != nil {
//	t.Fatal(err)
//}
//
//server := testHTTPServer()
//	for _, tt := range testCases {
//		compare, err := semVerComparison(tt.minVersion, client)
//		if err != nil {
//			t.Fatal(err)
//		}
//
//		if compare != tt.expected {
//			t.Fatalf("expected semantic version to return %t, got %t", tt.expected, compare)
//		}
//	}
//}
