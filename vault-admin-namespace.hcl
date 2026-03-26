ui = true
api_addr = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"
disable_mlock = true

# Configure administrative namespace
administrative_namespace_path = "admin/"

listener "tcp" {
  address = "127.0.0.1:8200"
  cluster_address = "127.0.0.1:8201"
  tls_disable = 1
}

storage "raft" {
  path = "./testdata/vault-admin-data/raft"
  node_id = "node1"
}f