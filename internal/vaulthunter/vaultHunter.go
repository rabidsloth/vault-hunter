package vaulthunter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"

	vapi "github.com/hashicorp/vault/api"
	vaws "github.com/hashicorp/vault/api/auth/aws"
	"gopkg.in/yaml.v2"
	apiv1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
)

// path and key vault secret
type KeyDef struct {
	Path   string `yaml:"path"`
	Key    string `yaml:"key"`
	Base64 bool   `yaml:"base64,omitempty"`
}

// map of vault secret locations
type KeyConfig map[string]KeyDef

type FullSecretConfigPaths []string

// secret config object
type SecretConfig struct {
	SecretName            string                `yaml:"secret_name"`
	KeyConfig             KeyConfig             `yaml:"key_config"`
	FullSecretConfigPaths FullSecretConfigPaths `yaml:"full_secret_config_paths"`
}

// configuration for vault-hunter
type AppConfig struct {
	configEnv            string
	displayHelp          bool
	envFileDirectory     string
	vaultHost            string
	vaultToken           string
	vhFolder             string
	kubeConfig           string
	kubeNamespace        string
	vconfig              *vapi.Config
	verifyConfig         bool
	secretNamePrefix     string
	secretNameSuffix     string
	apps                 []string
	appName              string
	projectID            string
	applyConfig          bool
	policyPrefix         string
	policyLockProdClaims bool
	dependencyApps       string
	removeExport         bool
}

var debug bool

// main entrypoint
// parses cli commands
func Cli() {
	creatCmd := flag.NewFlagSet("create", flag.ExitOnError)
	deleteCmd := flag.NewFlagSet("delete", flag.ExitOnError)
	helpCmd := flag.NewFlagSet("help", flag.ExitOnError)
	generateEnvFileCmd := flag.NewFlagSet("generate-env-file", flag.ExitOnError)
	generateAllPoliciesCmd := flag.NewFlagSet("generate-policies", flag.ExitOnError)

	if len(os.Args) <= 1 {
		help()
		helpCmd.Usage()
		os.Exit(1)
	}
	command := os.Args[1]
	switch command {
	case "delete":
		c := parseFlags(deleteCmd)
		c, err := parseVhFolder(c)
		if err != nil {
			log.Fatal(err)
		}
		checkEmpty("appname", c.appName)
		checkEmpty("vh-folder", c.vhFolder)
		client, err := getVaultClient(c.vconfig, c.vaultToken)
		if err != nil {
			log.Fatal(err)
		}
		deleteAllPoliciesAndRoles(c, client)
		os.Exit(0)
	case "help":
		parseFlags(helpCmd)
		help()
		helpCmd.Usage()
		os.Exit(0)
	case "create":
		c := parseFlags(creatCmd)
		c, err := parseVhFolder(c)
		if err != nil {
			log.Fatal(err)
		}
		checkEmpty("env", c.configEnv)
		checkEmpty("vault-url", c.vaultHost)
		checkEmpty("vault-token", c.vaultToken)
		checkEmpty("kube-config", c.kubeConfig)
		checkEmpty("namespace", c.kubeNamespace)
		checkEmpty("vh-folder", c.vhFolder)
		vclient, err := getVaultClient(c.vconfig, c.vaultToken)
		if err != nil {
			log.Fatal(err)
		}
		kclient, err := getKubeClient(c.kubeConfig, c.kubeNamespace)
		if err != nil {
			log.Fatalf("unable to get kube client: %s", err)
		}
		createSecrets(c, vclient, kclient)
	case "generate-env-file":
		c := parseFlags(generateEnvFileCmd)
		c, err := parseVhFolder(c)
		if err != nil {
			log.Fatal(err)
		}
		checkEmpty("env", c.configEnv)
		checkEmpty("vh-folder", c.vhFolder)
		checkEmpty("env-file-dir", c.envFileDirectory)
		client, err := getVaultClient(c.vconfig, c.vaultToken)
		if err != nil {
			log.Fatal(err)
		}
		for _, x := range c.apps {
			appFolder := c.vhFolder + "/" + x
			_, secrets, err := getSecrets(client, appFolder, c.configEnv)
			if err != nil {
				log.Fatal(err)
			}
			filename := c.envFileDirectory + "/" + x + "-" + c.configEnv + ".env"
			err = writeEnvFile(secrets, filename, c.removeExport)
			if err != nil {
				log.Fatal(err)
			}
		}
		os.Exit(0)
	case "generate-policies":
		c := parseFlags(generateAllPoliciesCmd)
		c, err := parseVhFolder(c)
		if err != nil {
			log.Fatal(err)
		}
		checkEmpty("appname", c.appName)
		checkEmpty("vh-folder", c.vhFolder)
		checkEmpty("project-id", c.projectID)
		client, err := getVaultClient(c.vconfig, c.vaultToken)
		if err != nil {
			log.Fatal(err)
		}
		err = genAllRolesAndPolicies(c, client)
		if err != nil {
			log.Fatal(err)
		}
	default:
		parseFlags(helpCmd)
		help()
		helpCmd.Usage()
		os.Exit(0)
	}
}

// checks if key is empty
func checkEmpty(key string, val string) bool {
	if val == "" {
		log.Fatalf("ERROR: missing required value: %s", key)
	}
	return false
}

// handles setting up and config of cli flags
func parseFlags(f *flag.FlagSet) (config AppConfig) {
	appNamePtr := f.String("appname", "", "name of app - required when 'generate-policies' is set")
	debugPtr := f.Bool("debug", false, "display debug logging")
	configEnvPtr := f.String("env", "", "name of the config environment, i.e. name of the 'environment.yaml' file within 'vh-folder'. Can also set with VH_ENV env var")
	vhFolderPtr := f.String("vh-folder", "vh", "folder of secret map yaml files. Can also set with VH_CONFIG_DIR env var - defaults to 'vh'")
	envFileDirectoryPtr := f.String("env-file-dir", ".", "directory for placing .env files when calling \"generate-env-file\"")
	vaultHostPtr := f.String("vault-url", "", "vault url. Can also set with VAULT_ADDR env var")
	vaultTokenPtr := f.String("vault-token", "", "vault token. Can also set with VAULT_TOKEN env var")
	kubeConfigPtr := f.String("kube-config", "", "location of kubectl config. Can also set with KUBECONFIG env var")
	kubeNamespacePtr := f.String("namespace", "", "kubernetes namespace to place secret. Can also set with KUBE_NAMESPACE env var")
	secretNamePrefixPtr := f.String("secret-name-prefix", "", "prefix for the kubernetes secret(s).")
	secretNameSuffixPtr := f.String("secret-name-suffix", "", "suffix for the kubernetes secret(s).")
	projectIDPtr := f.String("project-id", "", "gitlab projectID for application - needed for 'generate-policies'")
	policyLockProdClaimsPtr := f.Bool("policy-lock-prod-claims", true, "when generating policies, lock prod env to the master branch. Defaults true")
	policyPrefixPtr := f.String("policy-prefix", "vh", "prefix for all generated vault policies and roles - defaults to 'vh'")
	verifyPtr := f.Bool("verify", false, "set to true to only verify secrets defined in secmap exist in vault")
	applyConfigPtr := f.Bool("apply", false, "set to true to apply generated policies and roles to vault")
	dependencyAppsPtr := f.String("dependent-apps", "", "comma separated list of additional application names to add to created role for access via CI")
	removeExportPtr := f.Bool("remove-export", false, "set to remove export string from generated env file")
	displayHelpPtr := f.Bool("help", false, "display vault-hunter help")

	f.Parse(os.Args[2:])
	debug = *debugPtr
	config.appName = *appNamePtr
	config.configEnv = *configEnvPtr
	config.vhFolder = setVar("VH_CONFIG_DIR", vhFolderPtr)
	config.envFileDirectory = *envFileDirectoryPtr
	config.vaultHost = setVar("VAULT_ADDR", vaultHostPtr)
	config.vaultToken = setVar("VAULT_TOKEN", vaultTokenPtr)
	config.kubeConfig = setVar("KUBECONFIG", kubeConfigPtr)
	config.kubeNamespace = setVar("KUBE_NAMESPACE", kubeNamespacePtr)
	config.secretNamePrefix = *secretNamePrefixPtr
	config.secretNameSuffix = *secretNameSuffixPtr
	config.projectID = *projectIDPtr
	config.verifyConfig = *verifyPtr
	config.applyConfig = *applyConfigPtr
	config.displayHelp = *displayHelpPtr
	config.policyLockProdClaims = *policyLockProdClaimsPtr
	config.policyPrefix = *policyPrefixPtr
	config.dependencyApps = *dependencyAppsPtr
	config.removeExport = *removeExportPtr
	config.vconfig = &vapi.Config{
		Address: config.vaultHost,
	}
	return config
}

// find all non "generated" folders in vh folder, assume they are a maps folder for an app
func parseVhFolder(aConfig AppConfig) (appConfig AppConfig, err error) {
	dirList, err := ioutil.ReadDir(aConfig.vhFolder)
	if err != nil {
		return appConfig, err
	}
	var apps []string
	for _, f := range dirList {
		if f.IsDir() && f.Name() != "generated" {
			str := "adding " + f.Name() + " to app list..."
			debugLog(str, false)
			apps = append(apps, f.Name())
		}
	}
	aConfig.apps = apps
	return aConfig, nil
}

// translates sec map from vault, creates k8s secret
func createSecrets(c AppConfig, vclient *vapi.Client, secretsClient v1.SecretInterface) {
	debugLog("DEBUG: starting vault lookup...", false)
	for _, x := range c.apps {
		appFolder := c.vhFolder + "/" + x
		secretName, secrets, err := getSecrets(vclient, appFolder, c.configEnv)
		if err != nil {
			log.Fatalf("error getting secrets: %s", err)
		}
		if c.secretNamePrefix != "" {
			secretName = c.secretNamePrefix + "-" + secretName
		}
		if c.secretNameSuffix != "" {
			secretName = secretName + "-" + c.secretNameSuffix
		}
		debugLog("DEBUG: secret lookup successful", false)
		// don't create secret if in verify mode
		if !c.verifyConfig {
			err = createAppEnvConfigSecret(secretsClient, secretName, secrets)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("created or updated secret: %s", secretName)
		}
	}
}

// modified secret path to be kv2 compatabile (puts /data/ after store)
func modSecretPath(p string) string {
	re := regexp.MustCompile(`^[^/]*`)
	store := re.FindString(p)
	path := strings.Replace(p, store, "/data", 1)
	lookupPath := store + path
	return lookupPath
}

// pull secrets from vault
func getSecrets(client *vapi.Client, folder string, env string) (string, map[string]interface{}, error) {
	var secrets = make(map[string]interface{})
	var secretName string
	data := mergeConfig(folder, env)

	secretName = data.SecretName
	// process any full secret config paths - grabs all k/v from secret
	if data.FullSecretConfigPaths != nil {
		for _, x := range data.FullSecretConfigPaths {
			lookupPath := modSecretPath(x)
			secret, err := getSecret(lookupPath, client)
			if err != nil {
				return "", nil, err
			}
			m := secret.Data
			if secret.Data["data"] != nil {
				objects, ok := secret.Data["data"].(map[string]interface{})
				// throw error if the lookupKey doesn't exist in the secrets object
				if objects == nil {
					log.Print(objects)
					return "", nil, fmt.Errorf("secret %s returned empty - make sure key for exists in vault", lookupPath)
				}
				if !ok {
					return "", nil, fmt.Errorf("could not decode v2 secret")
				}
				m = objects
			}
			// grab all objects from secret, uppercase key and set as env var
			for k, v := range m {
				str := fmt.Sprintf("%v", v)
				upperKey := strings.ToUpper(k)
				// find and replace any env vars in secret value
				byteStr := []byte(str)
				finalSecretVal, err := resolveEnvVarsInString(byteStr, str)
				if err != nil {
					return "", nil, err
				}
				secrets[upperKey] = string(finalSecretVal)
			}
		}
	}
	for k, v := range data.KeyConfig {
		lookupPath := modSecretPath(v.Path)
		lookupKey := v.Key
		secret, err := getSecret(lookupPath, client)
		if err != nil {
			return "", nil, err
		}
		m := secret.Data
		// check if secret was pulled from kv-v2 and grab key from correct object
		if secret.Data["data"] != nil {
			objects, ok := secret.Data["data"].(map[string]interface{})
			// throw error if the lookupKey doesn't exist in the secrets object
			if objects[lookupKey] == nil {
				return "", nil, fmt.Errorf("key %s returned nil for secret %s - make sure key for exists in vault", lookupKey, lookupPath)
			}
			if !ok {
				return "", nil, fmt.Errorf("could not decode v2 secret")
			}
			m = objects
		}
		str := fmt.Sprintf("%v", m[lookupKey])
		// find and replace any env vars in secret value
		byteStr := []byte(str)
		finalSecretVal, err := resolveEnvVarsInString(byteStr, str)
		if err != nil {
			return "", nil, err
		}
		if v.Base64 {
			finalSecretVal = []byte(base64.StdEncoding.EncodeToString((finalSecretVal)))
		}
		secrets[k] = string(finalSecretVal)
		if debug {
			log.Printf("DEBUG: pulled secret: %s - %s/%s", k, lookupPath, lookupKey)
		}
	}
	return secretName, secrets, nil
}

func getSecret(lookupPath string, client *vapi.Client) (secret *vapi.Secret, err error) {
	debugLog("DEBUG: looking up secret: "+lookupPath, false)
	secret, err = client.Logical().Read(lookupPath)
	if err != nil {
		return nil, fmt.Errorf("unable to lookup vault vaults: %s", err)
	}
	// log.Print(secret.Warnings)
	if secret != nil {
		if len(secret.Warnings) > 0 {
			return nil, fmt.Errorf("got warning looking up secret: %s", secret.Warnings[0])
		}
	}

	if secret == nil {
		return nil, fmt.Errorf("key %s returned nil - make sure secret exists in vault", lookupPath)
	}
	return secret, nil
}

// return k8s client
func getKubeClient(kconfig string, namespace string) (v1.SecretInterface, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kconfig)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	secretClient := clientset.CoreV1().Secrets(namespace)
	return secretClient, nil
}

// create k8s secret
func createAppEnvConfigSecret(secretsClient v1.SecretInterface, secretName string, env map[string]interface{}) error {
	ctx := context.TODO()
	createOpts := metav1.CreateOptions{}
	updateOpts := metav1.UpdateOptions{}
	newSecret := new(apiv1.Secret)
	newSecret.Name = secretName
	newSecret.Type = apiv1.SecretTypeOpaque
	newSecret.Data = make(map[string][]byte)
	for k, v := range env {
		newSecret.Data[k] = []byte(fmt.Sprintf("%v", v))
	}
	if _, err := secretsClient.Create(ctx, newSecret, createOpts); err != nil {
		if apierrors.IsAlreadyExists(err) {
			log.Print("secret already exists, updating...")
			if _, err = secretsClient.Update(ctx, newSecret, updateOpts); err != nil {
				return fmt.Errorf("unable to update existing secret %s", err)
			}
			return nil
		}
		return fmt.Errorf("unable to create secret %s", err)
	}
	return nil
}

// read secmap and unmarshall it into struct
func parseSecretConfig(file string) (data SecretConfig) {
	yamlFile, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatalf("unable to read secret map file: %s", err)
	}
	// replace any dynamic env vars
	yamlFile, err = resolveEnvVarsInString(yamlFile, file)
	if err != nil {
		log.Fatalf("could not lookup env var: %s in map file: %s", err, file)
	}
	err = yaml.Unmarshal(yamlFile, &data)
	if err != nil {
		log.Fatal(err)
	}
	if debug {
		log.Printf("DEBUG: parsed data from secret map: %v", data)
	}

	return data
}

// replaces all {{ENV_VARS}} vars in provided string, stringIdentifier used for logging purposes
func resolveEnvVarsInString(fileBytes []byte, stringIdentifier string) (fullFile []byte, err error) {
	fileStr := string(fileBytes)
	re := regexp.MustCompile(`\{\{(.*?)\}\}`)
	submatchall := re.FindAllString(fileStr, -1)
	for _, envVar := range submatchall {
		trimmedEnvVar := strings.Trim(envVar, "{")
		trimmedEnvVar = strings.Trim(trimmedEnvVar, "}")
		v, exist := os.LookupEnv(trimmedEnvVar)
		if exist {
			fileStr = strings.ReplaceAll(fileStr, envVar, v)
		} else {
			fileStr = strings.ReplaceAll(fileStr, envVar, "ENV_VAR_NOT_FOUND")
			log.Printf("WARN: unable to lookup env var %s passed in string: %s", trimmedEnvVar, stringIdentifier)
		}
	}
	fullFile = []byte(fileStr)
	return fullFile, nil
}

// check if file exists
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// return vault client
func getVaultClient(clientConfig *vapi.Config, token string) (client *vapi.Client, err error) {
	client, err = vapi.NewClient(clientConfig)
	if token == "" {
		debugLog("DEBUG: VAULT_TOKEN not found, attempting AWS IAM auth", false)
		ctx := context.Background()
		a, err := vaws.NewAWSAuth(vaws.WithIAMAuth())
		if err != nil {
			return nil, err
		}
		_, err = client.Auth().Login(ctx, a)
		if err != nil {
			return nil, err
		}
		debugLog("DEBUG: successfully authenticated using AWS IAM", false)
	} else {
		client.SetToken(token)
	}
	if err != nil {
		return nil, err
	}

	return client, nil
}

// merges env and base config files
func mergeConfig(folder string, env string) (data SecretConfig) {
	var mergedConfig SecretConfig
	baseFile := folder + "/base.yaml"
	if !fileExists(baseFile) {
		baseFile = folder + "/dev.yaml"
	}
	if !fileExists(baseFile) {
		log.Fatalf("could not find basefile (base.yaml or dev.yaml): %s", baseFile)
	}
	envFile := folder + "/" + env + ".yaml"
	if !fileExists(envFile) {
		log.Printf("WARN: could not find %s env in folder %s, falling back to basefile: %s", env, folder, baseFile)
		envFile = baseFile
	}
	envConfig := parseSecretConfig(envFile)
	if fileExists(baseFile) && baseFile != envFile {
		baseConfig := parseSecretConfig(baseFile)
		b, err := json.Marshal(baseConfig)
		if err != nil {
			log.Panic(err)
		}
		if debug {
			debugLog(fmt.Sprintf("DEBUG: baseConfig:\n %s\n", b), false)
		}
		mergedConfig = baseConfig
		mergedConfig.SecretName = envConfig.SecretName
		// fullSecretPaths are appended from the env requested which will be processed last
		// as long as we can depend on the order of this array, the secrets will resolve/merge properly
		if mergedConfig.FullSecretConfigPaths == nil {
			mergedConfig.FullSecretConfigPaths = envConfig.FullSecretConfigPaths
		} else {
			mergedConfig.FullSecretConfigPaths = append(mergedConfig.FullSecretConfigPaths, envConfig.FullSecretConfigPaths...)
		}
		debugLog(fmt.Sprintf("DEBUG: mergedConfig.FullSecretConfigPaths = %s", mergedConfig.FullSecretConfigPaths), false)

		for x := range envConfig.KeyConfig {
			if mergedConfig.KeyConfig == nil {
				mergedConfig.KeyConfig = envConfig.KeyConfig
			} else {
				mergedConfig.KeyConfig[x] = envConfig.KeyConfig[x]
			}

		}
	} else {
		mergedConfig = envConfig
	}

	if debug {
		ec, err := json.Marshal(envConfig)
		if err != nil {
			log.Panic(err)
		}
		mc, err := json.Marshal(mergedConfig)
		if err != nil {
			log.Panic(err)
		}
		log.Printf("DEBUG: envConfig:\n %s\n", ec)
		log.Printf("DEBUG: mergedConfig:\n %s\n", mc)
	}
	return mergedConfig
}

// set env var and error if missing
func setVar(envVar string, flag *string) (val string) {
	if *flag == "" {
		val = os.Getenv(envVar)
	} else {
		val = *flag
	}

	return val
}

func writeEnvFile(secrets map[string]interface{}, filename string, removeExport bool) error {
	var envFileContents string
	var keys []string
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		var str string
		if removeExport {
			str = fmt.Sprintf("%s=\"%s\"\n", k, secrets[k])
		} else {
			str = fmt.Sprintf("export %s=\"%s\"\n", k, secrets[k])
		}

		envFileContents = envFileContents + str
	}
	contents := []byte(envFileContents)
	err := os.WriteFile(filename, contents, 0600)
	if err != nil {
		return err
	}
	log.Printf("created/updated env file: %s", filename)
	return nil
}

// display help
func help() {
	help := `
Vault Hunter

Description: Framework for pulling secrets from Vault and creates/updates k8s secrets

Usage: 
Requires a configdir with secret maps to get started - defaults to 'vh/'
'vh/':
	'appname'/:
		'base.yaml':
			secret_name: appname
			key_config:
				EXAMPLE_PASS:
					path: secret/machine/something/api
					key: SOMETHING_API_KEY
				EXAMPLE_PASS2:
					path: secret/machine/something2/api
					key: SOMETHING2_API_KEY
		'local.yaml':
			secret_name: appname
			key_config:
				DB_PASS:
					path: users/{{DEV_NAME}}/db/somedb/dev
					key: password
		'dev.yaml':
			secret_name: appname
			full_secret_config_paths:
				- config/app-two/dev
			key_config:
				EXAMPLE_PASS:
					path: secret/machine/something/dev/api
					key: SOMETHING_API_KEY
				EXAMPLE_PASS2:
					path: secret/machine/something2/dev/api
					key: SOMETHING2_API_KEY
		'prod.yaml':
			secret_name: appname
			key_config:
				EXAMPLE_PASS:
					path: secret/machine/something/prod/api
					key: SOMETHING_PROD_API_KEY
					base64: true

NOTES: 
  * map config is merged together:
		* if base.yaml exists, all environments will be merged with base.yaml
			duplicate items will resolve to whatever the environment is configured for, overwriting base
		* if base.yaml does not exist and a non-dev environment is called and a dev.yaml does exist, the dev.yaml will act as a base
		* neither base.yaml or dev.yaml are required
		* can have multple apps under vh/ folder
	* files named local.yaml will not have roles/policies generated as these perms should be tied to the user
	* qa.yaml files will generate gitlab roles which match "master" branch jwt so they can be deployed alongside master
	* dynamic variables are allows in maps
	  * variables between two brackets (no spaces) will be looked up from environment variables and replaced when parsing secret maps
		* ex. {{DEV_NAME}} will be replaced with the env var for $DEV_NAME
		* will error if variable cannot be looked up
	* can use "full_secret_config_paths" as a yaml list to simply grab all k/v pairs from secret path and add them to the secret list
		* full_secret_config_paths are also merged together, the env requested will be resolved last, overwriting any duplicates from the base/dev files
	* can use base64 on a key_config object to retrieve value as a base64 encoded value
	* passing --remove-export to generate-env-file will remove any 'export ' statements in file for apps with different needs 

---

Examples:

Generate policies and roles:
  vault-hunter generate-policies -project-id 60 -appname=testycat

Generate and apply policies and roles:
 	vault-hunter generate-policies -project-id 60 -appname=testycat -apply

Generate local env file:
	vault-hunter generate-env-file -env dev

Delete generated policies and roles from vault:
  vault-hunter delete

Verify vault-hunter can retrieve all secrets from compiled map:
	vault-hunter create -env prod -verify

Create/Update k8s secrets for 'prod' env with suffix:
	vault-hunter create -env prod -secret-name-suffix=issue-53


Commands [ create, generate-env-file, generate-policies, help ]

Required options:

	`

	fmt.Println(help)
}

func debugLog(s string, j bool) {
	if debug {
		if j {
			jb, err := json.Marshal(s)
			if err != nil {
				log.Printf("Unable to json marshal debug log: %s - %s", s, err)
			}
			log.Print(jb)
		} else {
			log.Print(s)
		}
	}
}
