// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendConfigCA_basic(t *testing.T) {
	var p *schema.Provider
	path := "pki-" + strconv.Itoa(acctest.RandInt())

	resourceName := "vault_pki_secret_backend_config_ca.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendConfigCAConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
				),
			},
		},
	})
}

func testPkiSecretBackendConfigCAConfig_basic(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "pki"
  description = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds = "8640000"
}

resource "vault_pki_secret_backend_config_ca" "test" {
  backend          = vault_mount.test.path
  pem_bundle       = <<EOT
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwvEHeJCXnFgi88rE1dTX6FHdBPK0wSjedh0ywVnCZxLWbBv/
5PytjTcCPdrfW7g2sfbPwOge/WF3X2KeYSP8SxZA0czmz6QDspeG921JkZWtyp5o
++N0leLTIUAhq339p3O1onAOUO1k4sHfmCwfrDpTn2hcx4URa5Pzzb1fHigusjIH
1mcGdncaA6Z2CzO1w4E8kPOUukIDrcZT4faOZrWUIQZKQw2JzTyKJ+ZMDCZq2TFz
WwpL3eG48wB7J7mibFQ/9nFvxpIflBjDAZ8QiqkwYr5N0DNsTxcfTCSeubfJDCUf
IWwFZhLitzwOxazazUQKXX/SPMQ1l/L9o3nnHwIDAQABAoIBAAQidJQcDPsl62fc
Txxx7TpiMhvewfKu2TkMGX18V+EzxxR364+BxHSQTB3fvIkHeTGBGJrw0WdyX8PI
Ja/NwZYeHLXWcLbKtcFd8WDiEoNh91Oq1HMzOc/MBcpYv94RSAX7MEkHs2YIAvHE
RufFV86hVhC1d/JLYjkz5CHi+Fd9XTYjBK78tHhJd4IJPu5LYvwlmzC1zeS7s1Tg
QW1FQuVDV8tWa4PMTrQHwfaGqn95AKc+tbg+ubpCiWl5bBNI3Ghuh4sAC9dMdAkd
w27i29O9/Y3XJSSGUZlZqDBP4YU388RgHpzLDUxgRcaQt9vdeEz6frULPW67e9D2
mPPDzjECgYEA4aPOwvnSwGoOKsS6vANGy4Ajsq09PR+1ltMJUR5kDlXGuZWI72eX
3/GAnovDuCp0tbYt0r7Fmkfel0Ore7SYM18TH5QGpPddcZLvKUf7AchCIOYY0Te3
pS9+7S1lEGrLXyuox4N26Ov6wHVrmZTcQoZsDWbjYxNNsNACsiQNjGMCgYEA3SvQ
Jets9e9SgNVvao2TijX+/vcNKRfcWB71T9Xc4BuSNEu5+ZLtptlwaSnVCVu1Xilk
sWDh+3EhByl4EteENPvE/7A2s1sfcDOprvg0r52aBZKeTp0AukrT8+Ad4hap7g1x
2Lz11MFDkhRqt2KqQaIL+5Mq5WfptbBJ0YI7ARUCgYAD6iSfK1hlsDFYupsGwgPL
agi0g97pHZC38idaOe3AdeqBs79xb9mpr/XsSj52Bn6J3IRFALxK5e5Nr4XdGo/9
bCvXw2iuGgCMBOGTVMVdDY1gJr3Ne2r7Oay5Dq2PMFsg5pACDhzVA6sRBbh9LKD5
on1jaiKNyHrzk1hIoOl/QwKBgA+Ov2uLbfS2yvTpDpdOMiyss603r6NOXF+Ofe8J
uinBhr1K/mAB59muveuH18Z6vv1KqByaFgtb39jjH+Eja9dWRns95/sh08pOuAbo
yrv3uBfgQmaBQMXZ8aLcBv4aXgWyyGlYkWpP1fL2oLMZq6RGQ9WEeqX8c0ImjmrA
YGopAoGBAJZPFlZi2Rfq4MfFZp/X1/zM09hphZwkxkSI+RnsjDUjTgB8CuQul5ep
KWE98yLw4C25Cqw5fKKQ2addizLnZCAIfJKVNRjYLWlWyGQydDEUzqwXlSLS9LVX
LxLkWDajIyjeFn21Ttb42L9pBo3TAQIxUenom/lP2SQTvCKBiPai
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUahce2sCO7Bom/Rznd5HsNAlr1NgwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0xODEyMDIwMTAxNDRaFw00NjEy
MTUwMTAxNDRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDC8Qd4kJecWCLzysTV1NfoUd0E8rTBKN52HTLBWcJn
EtZsG//k/K2NNwI92t9buDax9s/A6B79YXdfYp5hI/xLFkDRzObPpAOyl4b3bUmR
la3Knmj743SV4tMhQCGrff2nc7WicA5Q7WTiwd+YLB+sOlOfaFzHhRFrk/PNvV8e
KC6yMgfWZwZ2dxoDpnYLM7XDgTyQ85S6QgOtxlPh9o5mtZQhBkpDDYnNPIon5kwM
JmrZMXNbCkvd4bjzAHsnuaJsVD/2cW/Gkh+UGMMBnxCKqTBivk3QM2xPFx9MJJ65
t8kMJR8hbAVmEuK3PA7FrNrNRApdf9I8xDWX8v2jeecfAgMBAAGjUzBRMB0GA1Ud
DgQWBBQXGfrns8OqxTGKsXG5pDZS/WyyYDAfBgNVHSMEGDAWgBQXGfrns8OqxTGK
sXG5pDZS/WyyYDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCt
8aUX26cl2PgdIEByZSHAX5G+2b0IEtTclPkl4uDyyKRY4dVq6gK3ueVSU5eUmBip
JbV5aRetovGOcV//8vbxkZm/ntQ8Oo+2sfGR5lIzd0UdlOr5pkD6g3bFy/zJ+4DR
DAe8fklUacfz6CFmD+H8GyHm+fKmF+mjr4oOGQW6OegRDJHuiipUk2lJyuXdlPSa
FpNRO2sGbjn000ANinFgnFiVzGDnx0/G1Kii/6GWrI6rrdVmXioQzF+8AloWckeB
+hbmbwkwQa/JrLb5SWcBDOXSgtn1Li3XF5AQQBBjA3pOlyBXqnI94Irw89Lv9uPT
MUR4qFxeUOW/GJGccMUd
-----END CERTIFICATE-----
EOT
}
`, path)
}
