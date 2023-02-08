package vaulthunter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	vapi "github.com/hashicorp/vault/api"
	"github.com/zclconf/go-cty/cty"
)

type VaultRole struct {
	RoleType            string      `json:"role_type"`
	Policies            []string    `json:"policies"`
	TokenExplicitMaxTTL int         `json:"token_explicit_max_ttl"`
	UserClaim           string      `json:"user_claim"`
	BoundClaimsType     string      `json:"bound_claims_type"`
	BoundClaims         BoundClaims `json:"bound_claims"`
}

type BoundClaims struct {
	ProjectID string `json:"project_id"`
	Ref       string `json:"ref,omitempty"`
	RefType   string `json:"ref_type,omitempty"`
}

// apply vault policy
func applyPolicy(policyName string, filename string, client *vapi.Client) error {
	var reader io.Reader
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Error opening policy file: %s - %s", filename, err)
	}
	defer file.Close()
	reader = file
	// Read the policy
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		log.Fatalf("Error reading policy: %s", err)
	}
	rules := buf.String()

	if err := client.Sys().PutPolicy(policyName, rules); err != nil {
		log.Fatalf("Error uploading policy: %s", err)
	}
	log.Printf("INFO: successfully created/updated policy: %s", policyName)
	return nil
}

// apply auth/jwt/role
func applyRole(roleName string, filename string, client *vapi.Client) error {
	jsondata, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	var j map[string]interface{}
	json.Unmarshal(jsondata, &j)
	path := "auth/jwt/role/" + roleName
	_, err = client.Logical().Write(path, j)
	if err != nil {
		return err
	}
	log.Printf("INFO: successfully created/updated role: %s", roleName)
	return nil
}

// delete role from vault
func deleteRole(roleName string, client *vapi.Client) error {
	path := "auth/jwt/role/" + roleName
	_, err := client.Logical().Delete(path)
	if err != nil {
		return err
	}
	log.Printf("INFO: deleted role: %s", roleName)
	return nil
}

// delete policy from vault
func deletePolicy(policyName string, client *vapi.Client) error {
	err := client.Sys().DeletePolicy(policyName)
	if err != nil {
		return err
	}
	log.Printf("INFO: deleted policy: %s", policyName)
	return nil
}

// delete all roles and policies for this app from vault
func deleteAllPoliciesAndRoles(c AppConfig, client *vapi.Client) error {
	prefix := c.policyPrefix + "-"
	var envs []string
	// find all all envs in all apps
	for _, x := range c.apps {
		e, err := getEnvs(c.vhFolder + "/" + x)
		if err != nil {
			return err
		}
		for _, y := range e {
			if !containsString(envs, y) {
				envs = append(envs, y)
			}
		}
	}

	// for each env, delete policy/role for that prefix+mainAppName+env
	for _, x := range envs {
		name := prefix + c.appName + "-" + x
		err := deletePolicy(name, client)
		if err != nil {
			return err
		}
		err = deleteRole(name, client)
		if err != nil {
			return err
		}
	}
	log.Printf("deleted all policies and roles from vault")
	return nil
}

// checks if string is in a []string
func containsString(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

// traverse appfolder and identify all environments
func getEnvs(appFolder string) (envs []string, err error) {
	// log.Printf("trying to get envs for %s", appFolder)
	var envFiles []string
	err = filepath.Walk(appFolder,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if strings.Contains(info.Name(), "base.yaml") {
				debugLog(fmt.Sprintf("basefile found: %s", info.Name()), false)
				return nil
			}
			if strings.Contains(info.Name(), ".yaml") {
				envFiles = append(envFiles, info.Name())
				return nil
			}
			for _, x := range envFiles {
				debugLog(fmt.Sprintf("envFileDirectory found: %s", x), false)
			}
			return nil
		})
	if err != nil {
		return envFiles, err
	}
	for _, x := range envFiles {
		envName := strings.TrimSuffix(x, ".yaml")
		envs = append(envs, envName)
	}
	return envs, nil
}

// generate all apply all vault policies and roles for this app
func genAllRolesAndPolicies(c AppConfig, client *vapi.Client) error {
	prefix := c.policyPrefix + "-"
	genFolder(c.vhFolder)
	log.Printf("INFO: finding policies for %s", c.appName)
	policyFolder := c.vhFolder + "/generated/policies"
	roleFolder := c.vhFolder + "/generated/roles"
	log.Printf("INFO: will output polcies to %s", policyFolder)
	// loop through apps and generate policies
	// for _, x := range c.apps {

	// }
	var envs []string
	// find all all envs in all apps
	for _, x := range c.apps {
		e, err := getEnvs(c.vhFolder + "/" + x)
		if err != nil {
			return err
		}
		for _, y := range e {
			if !containsString(envs, y) {
				envs = append(envs, y)
			}
		}
	}
	// log.Printf("envs: %s", envs)
	// envs, err := getEnvs(c.vhFolder)
	// if err != nil {
	// 	return (err)
	// }

	for _, x := range envs {
		debugLog(fmt.Sprintf("env processed: %s", x), false)
	}
	for _, x := range envs {
		if x == "local" {
			debugLog("got local env, not creating roles and policies", false)
			continue
		}
		debugLog(fmt.Sprintf("Running genPolicy for env: %s", x), false)
		destPolicyFile := policyFolder + "/" + c.appName + "-" + x + ".hcl"
		destRoleFile := roleFolder + "/" + c.appName + "-" + x + ".json"
		err := genPolicy(destPolicyFile, c.vhFolder, c.apps, x)
		if err != nil {
			return err
		}
		prod := false
		if x == "prod" || x == "qa" {
			prod = true
		}
		var policies []string
		policies = append(policies, prefix+c.appName+"-"+x)
		if c.dependencyApps != "" {
			s := strings.Split(c.dependencyApps, ",")
			for _, y := range s {
				policies = append(policies, prefix+y+"-"+x)
			}
		}
		err = genRole(destRoleFile, policies, prod, c.projectID, c.policyLockProdClaims)
		if err != nil {
			return err
		}
		if c.applyConfig {
			policyName := c.appName + "-" + x
			err := applyPolicy(prefix+policyName, destPolicyFile, client)
			if err != nil {
				return (err)
			}
			applyRole(prefix+policyName, destRoleFile, client)
			if err != nil {
				return (err)
			}
		}
		log.Printf("INFO: generated policies added to: %s", policyFolder)
		log.Printf("INFO: generated roles added to: %s", roleFolder)
	}
	return nil
}

// generate individual policy file
func genPolicy(filename string, configFolder string, apps []string, env string) error {

	f, err := os.Create(filename)
	if err != nil {
		return (err)
	}
	defer f.Close()
	allKeys := make(KeyConfig)
	var fullSecretConfig FullSecretConfigPaths
	for _, x := range apps {
		folder := configFolder + "/" + x
		// checking if appFolder has desired env
		_, err := os.Stat(folder + "/" + env + ".yaml")
		if err == nil {
			kdata := mergeConfig(folder, env)
			fullSecretConfig = append(fullSecretConfig, kdata.FullSecretConfigPaths...)
			for k, v := range kdata.KeyConfig {
				allKeys[k] = v
			}
		} else {
			return err
		}
	}

	// sort secret keys to ensure consistent order
	keys := make([]string, 0, len(allKeys))
	for key := range allKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	sort.Strings(fullSecretConfig)
	createdPaths := make(map[string]bool)
	for _, v := range keys {
		k := allKeys[v]
		realPath := modSecretPath(k.Path)
		if !createdPaths[realPath] {
			err := writePolicy(realPath, f)
			if err != nil {
				return err
			}
			createdPaths[realPath] = true
		}

	}
	for _, v := range fullSecretConfig {
		realPath := modSecretPath(v)
		if !createdPaths[realPath] {
			err := writePolicy(realPath, f)
			if err != nil {
				return err
			}
			createdPaths[realPath] = true
		}

	}
	log.Printf("INFO: policy written to: %s", filename)
	return nil
}

// writes a read policy entry in file for path given
func writePolicy(path string, file *os.File) error {
	// replace any unresolved env vars with "+" in policy
	re := regexp.MustCompile(`[^/]+ENV_VAR_NOT_FOUND`)
	submatchAll := re.FindAllString(path, -1)
	for _, x := range submatchAll {
		path = strings.ReplaceAll(path, x, "+")
	}
	object := hclwrite.NewEmptyFile()
	rootBody := object.Body()
	objectBlock := rootBody.AppendNewBlock("path", []string{path})
	objectBody := objectBlock.Body()

	val := cty.StringVal("read")
	vals := []cty.Value{val}
	objectBody.SetAttributeValue("capabilities", cty.ListVal(vals))
	rootBody.AppendNewline()

	_, err2 := file.Write(object.Bytes())
	if err2 != nil {
		return (err2)
	}
	return nil
}

// generate individual role file
func genRole(filename string, policies []string, prod bool, projectID string, lockProdClaims bool) error {
	var b BoundClaims
	if prod && lockProdClaims {
		b.RefType = "branch"
		b.Ref = "master"
	}
	b.ProjectID = projectID

	role := VaultRole{
		RoleType:            "jwt",
		Policies:            policies,
		TokenExplicitMaxTTL: 60,
		UserClaim:           "user_email",
		BoundClaimsType:     "glob",
		BoundClaims:         b,
	}
	file, _ := json.MarshalIndent(role, "", " ")
	newLine := []byte("\n")
	file = append(file, newLine...)

	err := ioutil.WriteFile(filename, file, 0644)
	if err != nil {
		return err
	}
	return nil
}

// generate "generated" folders
func genFolder(vhFolder string) error {
	clearGenFolder(vhFolder)
	genFolder := vhFolder + "/generated/"
	if _, err := os.Stat(genFolder); os.IsNotExist(err) {
		err := os.Mkdir(genFolder, 0755)
		if err != nil {
			return fmt.Errorf("could not create generated folder: %s - %s", genFolder, err)
		}
		err = os.Mkdir(genFolder+"policies", 0755)
		if err != nil {
			return fmt.Errorf("could not create policy folder: %s - %s", genFolder+"policies", err)
		}
		err = os.Mkdir(genFolder+"roles", 0755)
		if err != nil {
			return fmt.Errorf("could not create roles folder: %s - %s", genFolder+"roles", err)
		}
	}
	return nil
}

// delete "generated" folder
func clearGenFolder(vhFolder string) error {
	err := os.RemoveAll(vhFolder + "/generated/")
	if err != nil {
		return (fmt.Errorf("could not deleted generated folder: %s", err))
	}
	return nil
}
