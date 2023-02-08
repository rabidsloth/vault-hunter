path "secret/data/location/one/somedep/admin" {
  capabilities = ["read"]
}

path "secret/data/someotherdep/+/cats" {
  capabilities = ["read"]
}

path "secret/data/location/one/anotherdep/prod" {
  capabilities = ["read"]
}

path "secret/data/location/one/config/app-two-client-dev" {
  capabilities = ["read"]
}

