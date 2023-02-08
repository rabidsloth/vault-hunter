# vault-hunter

## Hunts vault for secrets

### Overview

#### vault-hunter is a framework for managing vault secrets for k8s-applications

* vault-hunter utilizes a configuration folder, defaulted to `vh/`
  * `vh/maps`
      * this is where 'secret maps' go.
      * secret maps begin with a `base.yaml` file which includes all secrets to be mapped which are shared across app environments:
      * `base.yaml`:
        ```
        secret_name: testbasesecret
        key_config:
          EXAMPLE_PASS:
            path: secret/machine/something/api
            key: SOMETHING_API_KEY
          EXAMPLE_PASS2:
            path: secret/machine/something2/api
            key: SOMETHING2_API_KEY
        ```
      * other environments are defined via `{env}.yaml` files, these will be merged with `base.yaml` when generating policies and secrets. Keys from the environment specific yaml files will take precedence when merged with the base file. 
      * `prod.yaml`:
        ```
        secret_name: testprodsecret
        key_config:
          EXAMPLE_PASS:
            path: secret/machine/something/prod/api
            key: SOMETHING_PROD_API_KEY
        ```
        * in the above example, prod and base files will be merged together, and the duplicate key of `EXAMPLE_PASS` will get it's value from the `prod.yaml` map
        * resulting merged config:
          ```
          secret_name: testprodsecret
          key_config:
            EXAMPLE_PASS:
              path: secret/machine/something/prod/api
            key: SOMETHING_PROD_API_KEY
            EXAMPLE_PASS2:
              path: secret/machine/something2/api
              key: SOMETHING2_API_KEY
              base64: true
            ```
  * `vh/generated`
    * `/policies`
      * policies generated from secret maps will be placed here
    * `/roles`
      * roles generated from secret maps will be placed here
* once all of the maps have been added to the `vh/maps` folder, vault-hunter can generate vault roles and policies which utilize Gitlab's JWT endpoint so that projects can authenticate with Vault in pipelines. 
  * must have vault admin level access in `VAULT_TOKEN`
  * `vault-hunter generate-policies -project-id 60 -appname=testycat`
  * vault-hunter can create/delete roles/policies
    * `vault-hunter generate-policies -project-id 60 -appname=testycat -apply`
    * `vault-hunter delete`
* after roles and policies have been applied to vault, vault-hunter can be run in the application's deployment pipeline when to create a k8s secret from the env map.
  * `vault-hunter create -env prod`
  * can also be run in a 'verify-only' mode which will just ensure it's able to retrieve the values from the compiled map.
    * `vault-hunter create -env prod -verify`
* can use `base64` on a `key_config` object to retrieve value as base64 encoded value

### Options
```
Commands [ create, generate-policies, generate-env-file, help ]

  -apply
        set to true to apply generated policies and roles to vault
  -appname string
        name of app - required when 'generate-policies' is set
  -config-folder string
        folder of secret map yaml files. Can also set with VH_CONFIG_DIR env var - defaults to 'vh' (default "vh")
  -debug
        display debug logging
  -env string
        name of the config environment, i.e. name of the 'environment.yaml' file within 'config-folder'. Can also set with VH_ENV env var
  -help
        display vault-hunter help
  -kube-config string
        location of kubectl config. Can also set with KUBECONFIG env var
  -namespace string
        kubernetes namespace to place secret. Can also set with KUBE_NAMESPACE env var
  -policy-prefix string
        prefix for all generated vault policies and roles - defaults to 'vh' (default "vh")
  -project-id string
        gitlab projectID for application - needed for 'generate-policies'
  -remove-exports
        requires `generate-env-file`, removed `export ` string from generated env files
  -secret-name string
        name for the kubernetes secret. If unset will default what secret_name is set to in secret map
  -vault-token string
        vault token. Can also set with VAULT_TOKEN env var
  -vault-url string
        vault url. Can also set with VAULT_ADDR env var
  -verify
        set to true to only verify secrets defined in secmap exist in vault
```
