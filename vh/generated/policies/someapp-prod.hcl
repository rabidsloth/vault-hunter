path "secrets/data/yetanotherdep/dev/app-two" {
  capabilities = ["read"]
}

path "config/data/app-one/prod" {
  capabilities = ["read"]
}

path "secrets/data/db/somedb/prod/app-one" {
  capabilities = ["read"]
}

path "config/data/app-two/api/base" {
  capabilities = ["read"]
}

path "secrets/data/app-one/app-two/dev" {
  capabilities = ["read"]
}

path "config/data/app-one/base" {
  capabilities = ["read"]
}

path "secrets/data/rabbitmq/prod/app-one" {
  capabilities = ["read"]
}

path "config/data/app-two/client/base" {
  capabilities = ["read"]
}

path "config/data/app-two/client/prod" {
  capabilities = ["read"]
}

