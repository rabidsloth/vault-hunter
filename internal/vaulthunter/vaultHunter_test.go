package vaulthunter

import (
	"bytes"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	hlog "github.com/hashicorp/go-hclog"
	jwt "github.com/hashicorp/vault-plugin-auth-jwt"
	kv "github.com/hashicorp/vault-plugin-secrets-kv"
	vapi "github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	hashivault "github.com/hashicorp/vault/vault"
	"k8s.io/client-go/kubernetes/fake"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

// all tests requiring the test server should go here to avoid spinning up multiple test servers
func Test_withVaultServer(t *testing.T) {
	client := createTestVault(t)

	// createSecret tests
	c := AppConfig{
		vhFolder:  "./../../mocks/vh",
		configEnv: "dev",
	}
	kubeClient := fake.NewSimpleClientset()
	secretClient := kubeClient.CoreV1().Secrets("test")
	vclient := createTestVault(t)
	type createSecretsArgs struct {
		c             AppConfig
		vclient       *vapi.Client
		secretsClient v1.SecretInterface
	}
	testCreateSecrets := []struct {
		name string
		args createSecretsArgs
	}{
		{
			name: "createSecretsTest",
			args: createSecretsArgs{
				c:             c,
				vclient:       vclient,
				secretsClient: secretClient,
			},
		},
	}
	for _, tt := range testCreateSecrets {
		t.Run(tt.name, func(t *testing.T) {
			createSecrets(tt.args.c, tt.args.vclient, tt.args.secretsClient)
		})
	}
	// getSecrets tests
	type getSecretArgs struct {
		client *vapi.Client
		folder string
		env    string
	}
	testGetSecret := []struct {
		name    string
		args    getSecretArgs
		want    string
		want1   map[string]interface{}
		wantErr bool
	}{
		{
			name: "getSecretsTestDev",
			args: getSecretArgs{
				client: client,
				folder: "./../../mocks/vh/app-two-api/",
				env:    "dev",
			},
			want: "app-two-api",
			want1: map[string]interface{}{
				"EXAMPLE_PASS":                 "imadirtysecret" + "-2",
				"ADMIN_USER_OVERRIDE":          "imadirtysecret" + "-3",
				"ANOTHERDEP_SECURITY_GROUP_ID": "imadirtysecret" + "-7",
			},
			wantErr: false,
		},
		{
			name: "getSecretsTestProd",
			args: getSecretArgs{
				client: client,
				folder: "./../../mocks/vh/app-two-api",
				env:    "prod",
			},
			want: "app-two-api",
			want1: map[string]interface{}{
				"EXAMPLE_PASS":                 "imadirtysecret" + "-1",
				"ADMIN_USER_OVERRIDE":          "aW1hZGlydHlzZWNyZXQtMw==",
				"EXAMPLE_PASS2":                "imadirtysecret" + "-4",
				"ANOTHERDEP_SECURITY_GROUP_ID": "imadirtysecret" + "-7",
			},
			wantErr: false,
		},
		{
			name: "getSecretsTestFullSecret",
			args: getSecretArgs{
				client: client,
				folder: "./../../mocks/vh/someotherapp",
				env:    "prod",
			},
			want: "someotherapp",
			want1: map[string]interface{}{
				"EXAMPLE_PASS":        "imadirtysecret" + "-2",
				"ADMIN_USER_OVERRIDE": "imadirtysecret" + "-3",
				"EXAMPLE_PASS2":       "imadirtysecret" + "-4",
				"VAR1":                "imadirtysecret" + "-10",
				"VAR2":                "imadirtysecret" + "-12",
				"VAR3":                "imadirtysecret" + "-13",
				"SOME_OTHER_STUFF":    "kittyCatPants",
			},
			wantErr: false,
		},
	}
	for _, tt := range testGetSecret {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("VAR_TO_BE_REPLACED", "kittyCatPants")
			got, got1, err := getSecrets(tt.args.client, tt.args.folder, tt.args.env)
			if (err != nil) != tt.wantErr {
				t.Errorf("getSecrets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getSecrets() \ngot = \n%v, \nwant = \n%v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("getSecrets() \ngot1 = \n%v, \nwant = \n%v", got1, tt.want1)
			}
		})
	}

	// applyPolicy tests
	type testCreateandDeleteArgs struct {
		policyName string
		filename   string
		client     *vapi.Client
	}
	testCreateandDelete := []struct {
		name    string
		args    testCreateandDeleteArgs
		wantErr bool
	}{
		{
			name: "applyPolicyTest",
			args: testCreateandDeleteArgs{
				policyName: "test-policy",
				filename:   "./../../mocks/generated/policies/testapp-dev.hcl",
				client:     client,
			},
			wantErr: false,
		},
	}
	for _, tt := range testCreateandDelete {
		t.Run(tt.name, func(t *testing.T) {
			if err := applyPolicy(tt.args.policyName, tt.args.filename, tt.args.client); (err != nil) != tt.wantErr {
				t.Errorf("applyPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err := deletePolicy(tt.args.policyName, tt.args.client); (err != nil) != tt.wantErr {
				t.Errorf("deletePolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	// genAllRolesAndPolicies test
	type testPolicyArgs struct {
		c AppConfig
	}
	testsPolicy := []struct {
		name    string
		args    testPolicyArgs
		wantErr bool
	}{
		{
			name: "testgenAllRolesAndPoliciesDev",
			args: testPolicyArgs{
				c: AppConfig{
					appName:              "testapp",
					apps:                 []string{"app-two-api", "app-two-client"},
					vhFolder:             "./../../mocks/vh",
					projectID:            "15",
					policyLockProdClaims: true,
					policyPrefix:         "vh",
					dependencyApps:       "app-two-api,app-two-client",
				},
			},
		},
		{
			name: "testGenAndApplyAllPoliciesDev",
			args: testPolicyArgs{
				c: AppConfig{
					appName:              "testapp",
					apps:                 []string{"app-two-api", "app-two-client"},
					vhFolder:             "./../../mocks/vh",
					projectID:            "15",
					policyLockProdClaims: true,
					policyPrefix:         "vh",
					applyConfig:          true,
					dependencyApps:       "app-two-api,app-two-client",
				},
			},
		},
	}
	for _, tt := range testsPolicy {
		t.Run(tt.name, func(t *testing.T) {
			// var client *vapi.Client
			if err := genAllRolesAndPolicies(tt.args.c, client); (err != nil) != tt.wantErr {
				t.Errorf("genAllRolesAndPolicies() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.args.c.applyConfig {
				if err := deleteAllPoliciesAndRoles(tt.args.c, client); (err != nil) != tt.wantErr {
					t.Errorf("deleteAll() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})

		// verify files exist
		var genFiles []string
		err := filepath.Walk("./../../mocks/vh/generated",
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				genFiles = append(genFiles, info.Name())
				return nil
			})
		if err != nil {
			t.Error(err)
		}

		var mockFiles []string
		err = filepath.Walk("./../../mocks/generated",
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					t.Error(err)
				}
				mockFiles = append(mockFiles, info.Name())
				return nil
			})
		if err != nil {
			t.Error(err)
		}

		for x, y := range genFiles {
			if y != mockFiles[x] {
				t.Errorf("filelist of generated policies and roles does not equal mock list. \nGot: %v\nWant: %v\n", mockFiles, genFiles)
			}
			if !strings.Contains(y, ".hcl") && !strings.Contains(y, ".json") {
				continue
			}
			mockFolder := "./../../mocks/generated/"
			genFolder := "./../../mocks/vh/generated/"
			subFolder := "policies/"
			if strings.Contains(y, "json") {
				subFolder = "roles/"
			}
			genFilePath := genFolder + subFolder + y
			mockFilePath := mockFolder + subFolder + y

			genFile, err1 := ioutil.ReadFile(genFilePath)
			if err1 != nil {
				t.Errorf("could not read generated file: %s - %s", genFilePath, err1)
			}

			mockFile, err1 := ioutil.ReadFile(mockFilePath)
			if err1 != nil {
				t.Errorf("could not read mock generated file: %s - %s", mockFilePath, err1)
			}
			if !bytes.Equal(genFile, mockFile) {
				t.Errorf("role file did not result in expected output: \nGot: \nFile: %v\n\n%v \nWanted: \nFile: %v\n%v", genFilePath, string(genFile), mockFilePath, string(mockFile))
			}
		}

		t.Cleanup(func() {
			err := os.RemoveAll(tt.args.c.vhFolder + "/generated")
			if err != nil {
				t.Errorf("unable to clean up generated polices folder: %s -  %v", tt.args.c.vhFolder+"/generated", err)
			}
		})
	}
	type applyRoleargs struct {
		roleName string
		filename string
		client   *vapi.Client
	}
	testApplyRoles := []struct {
		name    string
		args    applyRoleargs
		wantErr bool
	}{
		{
			name: "applyRoleTest",
			args: applyRoleargs{
				roleName: "test-role",
				filename: "./../../mocks/generated/roles/testapp-dev.json",
				client:   client,
			},
			wantErr: false,
		},
	}
	for _, tt := range testApplyRoles {
		t.Run(tt.name, func(t *testing.T) {
			if err := applyRole(tt.args.roleName, tt.args.filename, tt.args.client); (err != nil) != tt.wantErr {
				t.Errorf("applyRole() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err := deleteRole(tt.args.roleName, tt.args.client); (err != nil) != tt.wantErr {
				t.Errorf("deleteRole() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func createTestVault(t *testing.T) *vapi.Client {
	t.Helper()

	testData := KeyConfig{
		"1": {
			Path: "secret/data/location/one/conduit/api",
			Key:  "CONDUIT_API_KEY",
		},
		"2": {
			Path: "secret/data/location/one/anotherdep/prod",
			Key:  "anotherdep-verification-token",
		},
		"3": {
			Path: "secret/data/location/one/somedep/admin",
			Key:  "username",
		},
		"4": {
			Path: "secret/data/location/one/redis/prod/app-three",
			Key:  "APP_THREE_INDEX_REDIS_PASSWORD",
		},
		"5": {
			Path: "secret/data/location/one/somedep/test",
			Key:  "test-username",
		},
		"6": {
			Path: "secret/data/location/one/redis/test/app-three",
			Key:  "APP_THREE_INDEX_REDIS_PASSWORD",
		},
		"7": {
			Path: "config/data/machine/anotherdep/base",
			Key:  "ANOTHERDEP_SECURITY_GROUP_ID",
		},
		"8": {
			Path: "secret/data/location/one/redis/test/app-two-client",
			Key:  "SOME_SILLY_THING",
		},
		"9": {
			Path: "secret/data/location/one/turbo/dev/app-two-client",
			Key:  "SOME_OTHER_SILLY_THING",
		},
		"10": {
			Path: "secret/data/location/one/config/app-two-client-prod",
			Key:  "VAR1",
		},
		"14": {
			Path: "secret/data/location/one/config/mykittycat",
			Key:  "ENV_VAR_REPLACEMENT",
		},
	}

	// this is for testing a secret with multiple keys
	secretSets := KeyConfig{
		"11": {
			Path: "secret/data/location/one/config/app-two-client-dev",
			Key:  "VAR1",
		},
		"12": {
			Path: "secret/data/location/one/config/app-two-client-dev",
			Key:  "VAR2",
		},
		"13": {
			Path: "secret/data/location/one/config/app-two-client-dev",
			Key:  "VAR3",
		},
	}

	coreConfig := &hashivault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"kv2": kv.Factory,
		},
		CredentialBackends: map[string]logical.Factory{
			"jwt": jwt.Factory,
		},
	}
	cluster := hashivault.NewTestCluster(t, coreConfig, &hashivault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		Logger:      logging.NewVaultLogger(hlog.Error),
	})
	cluster.Start()

	client := cluster.Cores[0].Client
	err := client.Sys().Unmount("secret")
	if err != nil {
		log.Fatal(err)
	}
	err = client.Sys().Mount("secret", &vapi.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	err = client.Sys().Mount("config", &vapi.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	err = client.Sys().EnableAuthWithOptions("jwt", &vapi.EnableAuthOptions{
		Type: "jwt",
	})
	if err != nil {
		t.Error(err)
	}
	for k, v := range testData {
		var value string
		if strings.Contains(v.Key, "ENV_VAR_REPLACEMENT") {
			value = "{{VAR_TO_BE_REPLACED}}"
		} else {
			value = "imadirtysecret" + "-" + k
		}
		_, err = client.Logical().Write(v.Path, map[string]interface{}{
			v.Key: value,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	secObject := make(map[string]interface{})
	for k := range secretSets {
		value := "imadirtysecret" + "-" + k
		secObject[secretSets[k].Key] = value
	}
	_, err = client.Logical().Write(secretSets["11"].Path, secObject)
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func Test_setVar(t *testing.T) {
	type args struct {
		envVar string
		flag   string
	}
	tests := []struct {
		name    string
		args    args
		wantVal string
	}{
		{name: "envVarAndOptionTest", args: args{envVar: "VH_ENV_VAR", flag: "thing2"}, wantVal: "thing2"},
		{name: "envVarTest", args: args{envVar: "VH_ENV_VAR", flag: ""}, wantVal: "thing"},
		{name: "flagTest", args: args{envVar: "", flag: "flaggy"}, wantVal: "flaggy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flagPtr := &tt.args.flag
			os.Setenv(tt.args.envVar, tt.wantVal)
			if gotVal := setVar(tt.args.envVar, flagPtr); gotVal != tt.wantVal {
				t.Errorf("setVar() = %v, want %v", gotVal, tt.wantVal)
			}
		})
	}
}

func Test_mergeConfig(t *testing.T) {
	type args struct {
		folder string
		env    string
	}
	tests := []struct {
		name     string
		args     args
		wantData SecretConfig
	}{
		{name: "testMergeConfigDev",
			args: args{folder: "./../../mocks/vh/app-two-api/",
				env: "dev"},
			wantData: SecretConfig{
				SecretName: "app-two-api",
				KeyConfig: KeyConfig{
					"EXAMPLE_PASS": KeyDef{
						Path: "secret/machine/anotherdep/prod",
						Key:  "anotherdep-verification-token"},
					"ADMIN_USER_OVERRIDE": KeyDef{
						Path: "secret/machine/somedep/admin",
						Key:  "username"},
					"ANOTHERDEP_SECURITY_GROUP_ID": KeyDef{
						Path: "config/machine/anotherdep/base",
						Key:  "ANOTHERDEP_SECURITY_GROUP_ID"}}}},
		{name: "testMergeConfigTest",
			args: args{folder: "./../../mocks/vh/app-two-api/",
				env: "test"},
			wantData: SecretConfig{
				SecretName: "app-two-api",
				KeyConfig: KeyConfig{
					"EXAMPLE_PASS": KeyDef{
						Path: "secret/machine/conduit/api",
						Key:  "CONDUIT_API_KEY"},
					"ADMIN_USER_OVERRIDE": KeyDef{
						Path: "secret/machine/somedep/test",
						Key:  "test-username"},
					"EXAMPLE_PASS2": KeyDef{
						Path: "secret/machine/redis/test/app-three",
						Key:  "APP_THREE_INDEX_REDIS_PASSWORD"},
					"ANOTHERDEP_SECURITY_GROUP_ID": KeyDef{
						Path: "config/machine/anotherdep/base",
						Key:  "ANOTHERDEP_SECURITY_GROUP_ID"}}}},
		{name: "testMergeConfigWithoutBase",
			args: args{folder: "./../../mocks/vh/someotherapp/",
				env: "test"},
			wantData: SecretConfig{
				SecretName:            "someotherapp",
				FullSecretConfigPaths: []string{"secret/machine/config/app-two-client-dev"},
				KeyConfig: KeyConfig{
					"EXAMPLE_PASS": KeyDef{
						Path: "secret/machine/anotherdep/prod",
						Key:  "anotherdep-verification-token"},
					"ADMIN_USER_OVERRIDE": KeyDef{
						Path: "secret/machine/somedep/test",
						Key:  "test-username"},
					"EXAMPLE_PASS2": KeyDef{
						Path: "secret/machine/redis/test/app-three",
						Key:  "APP_THREE_INDEX_REDIS_PASSWORD"},
					"SOME_OTHER_STUFF": KeyDef{
						Path: "secret/machine/config/mykittycat",
						Key:  "ENV_VAR_REPLACEMENT"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotData := mergeConfig(tt.args.folder, tt.args.env); !reflect.DeepEqual(gotData, tt.wantData) {
				t.Errorf("mergeConfig() \ngot = \n%v, \nwant \n%v", gotData, tt.wantData)
			}
		})
	}
}

func Test_getVaultClient(t *testing.T) {
	type args struct {
		clientConfig *vapi.Config
		token        string
	}
	tests := []struct {
		name string
		args args
		// wantClient *vapi.Client
		wantErr bool
	}{
		{
			name: "testGetVaultClient",
			args: args{
				clientConfig: &vapi.Config{
					Address: "http://localhost",
				},
				token: "sometoken",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getVaultClient(tt.args.clientConfig, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("getVaultClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_help(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "helpTest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			help()
		})
	}
}

func Test_createAppEnvConfigSecret(t *testing.T) {
	kubeClient := fake.NewSimpleClientset()
	secretClient := kubeClient.CoreV1().Secrets("test")
	type args struct {
		secretsClient v1.SecretInterface
		secretName    string
		env           map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "createK8sSecretTest",
			args: args{
				secretsClient: secretClient,
				secretName:    "testyboi",
				env: map[string]interface{}{
					"TESTKEY":  "somepassword",
					"TESTKEY2": "someotherpassword",
				},
			},
			wantErr: false,
		},
		{
			name: "createK8sSecretDuplicateTest",
			args: args{
				secretsClient: secretClient,
				secretName:    "testyboi",
				env: map[string]interface{}{
					"TESTKEY":  "somepassword2",
					"TESTKEY2": "someotherpassword2",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := createAppEnvConfigSecret(tt.args.secretsClient, tt.args.secretName, tt.args.env); (err != nil) != tt.wantErr {
				t.Errorf("createAppEnvConfigSecret() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_getKubeClient(t *testing.T) {
	type args struct {
		kconfig   string
		namespace string
	}
	tests := []struct {
		name string
		args args
		// want    v1.SecretInterface
		wantErr bool
	}{
		{
			name: "getKubeClientTest",
			args: args{
				kconfig:   "./../../mocks/kubeconfig",
				namespace: "default",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getKubeClient(tt.args.kconfig, tt.args.namespace)
			if (err != nil) != tt.wantErr {
				t.Errorf("getKubeClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

// needs work, picks up too many env vars
func Test_parseFlags(t *testing.T) {
	tests := []struct {
		name       string
		wantConfig AppConfig
	}{
		{
			name: "parseFlagsTest",
			wantConfig: AppConfig{
				vhFolder:             "vh",
				envFileDirectory:     ".",
				policyLockProdClaims: true,
				policyPrefix:         "vh",
				vconfig: &vapi.Config{
					Address: "",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			createCmd := flag.NewFlagSet("create", flag.ExitOnError)
			os.Setenv("VAULT_TOKEN", "")
			os.Setenv("VAULT_ADDR", "")
			os.Setenv("KUBE_CONFIG", "")
			// have to define flags that go test is sending so parse doesn't panic
			createCmd.Bool("test.v", false, "something")
			createCmd.String("test.timeout", "", "something")
			createCmd.String("test.coverprofile", "", "something")
			createCmd.String("test.paniconexit0", "", "something")
			createCmd.Int("test.cpu", 1, "")
			createCmd.Set("vh-folder", "./../mocks/vh")
			if gotConfig := parseFlags(createCmd); !reflect.DeepEqual(gotConfig, tt.wantConfig) {
				log.Print(gotConfig.vconfig.Address)
				t.Errorf("parseFlags() = %v, want %v", gotConfig, tt.wantConfig)
			}

		})
	}
}

func Test_writeEnvFile(t *testing.T) {
	type args struct {
		secrets      map[string]interface{}
		filename     string
		removeExport bool
	}
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		wantString string
	}{
		{
			name: "writeEnvFileTest",
			args: args{
				secrets: map[string]interface{}{
					"EXAMPLE_1": "something",
					"EXAMPLE_2": "anotherthing",
				},
				filename:     "./../../mocks/vh/.env",
				removeExport: false,
			},
			wantErr: false,
			wantString: `export EXAMPLE_1="something"
export EXAMPLE_2="anotherthing"` + "\n",
		},
		{
			name: "writeEnvFileTestWithoutExport",
			args: args{
				secrets: map[string]interface{}{
					"EXAMPLE_1": "something",
					"EXAMPLE_2": "anotherthing",
				},
				filename:     "./../../mocks/vh/.env",
				removeExport: true,
			},
			wantErr: false,
			wantString: `EXAMPLE_1="something"
EXAMPLE_2="anotherthing"` + "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := writeEnvFile(tt.args.secrets, tt.args.filename, tt.args.removeExport); (err != nil) != tt.wantErr {
				t.Errorf("writeEnvFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			f1, err1 := ioutil.ReadFile(tt.args.filename)
			if err1 != nil {
				t.Errorf("could not read generated policy file: %s", err1)
			}
			if string(f1) != tt.wantString {
				t.Errorf("policy file did not result in expected output: \nGot: \n%v \nWanted: \n%v", string(f1), string([]byte(tt.wantString)))
			}
			t.Cleanup(func() {
				err := os.RemoveAll(tt.args.filename)
				if err != nil {
					t.Errorf("unable to clean up generated folder: %v", err)
				}
			})
		})
	}
}

func Test_replaceMapVars(t *testing.T) {
	type args struct {
		fileBytes []byte
	}
	tests := []struct {
		name         string
		args         args
		wantFullFile []byte
		wantErr      bool
	}{
		{
			name: "replaceMapVars",
			args: args{
				fileBytes: []byte("my {{ANIMAL}} is at the dentist"),
			},
			wantFullFile: []byte("my trex is at the dentist"),
			wantErr:      false,
		},
		{
			name: "replaceMapVars2",
			args: args{
				fileBytes: []byte("my {{FRANK}} is at the dentist"),
			},
			wantFullFile: []byte("my ENV_VAR_NOT_FOUND is at the dentist"),
			wantErr:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("ANIMAL", "trex")
			gotFullFile, err := resolveEnvVarsInString(tt.args.fileBytes, "yourmomshouse.yaml")
			if (err != nil) != tt.wantErr {
				t.Errorf("replaceMapVars() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotFullFile, tt.wantFullFile) {
				t.Errorf("replaceMapVars() = %v, want %v", string(gotFullFile), string(tt.wantFullFile))
			}
		})
	}
}
