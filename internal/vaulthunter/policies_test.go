package vaulthunter

import (
	"bytes"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func Test_getEnvs(t *testing.T) {
	type args struct {
		vhFolder string
	}
	tests := []struct {
		name     string
		args     args
		wantEnvs []string
		wantErr  bool
	}{
		{name: "getEnvsTest", args: args{vhFolder: "./../../mocks/vh/app-two-api"}, wantEnvs: []string{"dev", "prod", "test"}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEnvs, err := getEnvs(tt.args.vhFolder)
			if (err != nil) != tt.wantErr {
				t.Errorf("getEnvs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotEnvs, tt.wantEnvs) {
				t.Errorf("getEnvs() = %v, want %v", gotEnvs, tt.wantEnvs)
			}
		})
	}
}

func Test_genFolder(t *testing.T) {
	type args struct {
		vhFolder string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "genFolderTest", args: args{vhFolder: "./../../mocks/vh"}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := genFolder(tt.args.vhFolder); (err != nil) != tt.wantErr {
				t.Errorf("genFolder() error = %v, wantErr %v", err, tt.wantErr)
			}
			if _, err := os.Stat("./../../mocks/vh/generated"); os.IsNotExist(err) {
				t.Errorf("generated folder wasn't created: %v", err)
			}
			t.Cleanup(func() {
				err := os.RemoveAll("./../../mocks/vh/generated")
				if err != nil {
					t.Errorf("unable to clean up generated folder: %v", err)
				}
			})

		})
	}
}

func Test_genPolicy(t *testing.T) {
	type args struct {
		filename     string
		configFolder string
		env          string
		apps         []string
	}
	tests := []struct {
		name               string
		args               args
		wantErr            bool
		wantFileComparison string
	}{
		{
			name: "testGenPolicyDev",
			args: args{
				filename:     "./../../mocks/test-policy.hcl",
				configFolder: "./../../mocks/vh",
				apps:         []string{"app-two-api", "app-two-client"},
				env:          "dev",
			},
			wantErr:            false,
			wantFileComparison: "./../../mocks/policies/test-dev-policy.hcl"},
		{
			name: "testGenPolicyDevWithUnknownEnvVar",
			args: args{
				filename:     "./../../mocks/test-policy-with-unknown.hcl",
				configFolder: "./../../mocks/vh",
				apps:         []string{"yetanotherapp"},
				env:          "dev",
			},
			wantErr:            false,
			wantFileComparison: "./../../mocks/policies/test-dev-with-unknown-policy.hcl"},
		{
			name: "testGenPolicyProd",
			args: args{
				filename:     "./../../mocks/prod-policy.hcl",
				configFolder: "./../../mocks/vh",
				apps:         []string{"app-two-api", "app-two-client"},
				env:          "prod",
			},
			wantErr:            false,
			wantFileComparison: "./../../mocks/policies/test-prod-policy.hcl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := genPolicy(tt.args.filename, tt.args.configFolder, tt.args.apps, tt.args.env); (err != nil) != tt.wantErr {
				t.Errorf("genPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			f1, err1 := ioutil.ReadFile(tt.args.filename)
			if err1 != nil {
				t.Errorf("could not read generated policy file: %s", err1)
			}

			f2, err1 := ioutil.ReadFile(tt.wantFileComparison)
			if err1 != nil {
				t.Errorf("could not read test policy file: %s - %s", tt.wantFileComparison, err1)
			}
			if !bytes.Equal(f1, f2) {
				t.Errorf("policy file did not result in expected output: \nGot: \nFile: %v\n%v \nWanted: \nFile: %v\n%v", tt.args.filename, string(f1), tt.wantFileComparison, string(f2))
			}

			t.Cleanup(func() {
				err := os.RemoveAll(tt.args.filename)
				if err != nil {
					t.Errorf("unable to clean up generated file: %s -  %v", tt.args.filename, err)
				}
			})

		})
	}
}

func Test_genRole(t *testing.T) {
	type args struct {
		filename       string
		policies       []string
		prod           bool
		projectID      string
		lockProdClaims bool
	}
	tests := []struct {
		name               string
		args               args
		wantErr            bool
		wantFileComparison string
	}{
		{
			name: "genRoleTestDev",
			args: args{
				filename:       "./../../mocks/dev-role.json",
				policies:       []string{"vh-test-dev"},
				prod:           false,
				projectID:      "15",
				lockProdClaims: true,
			},
			wantErr:            false,
			wantFileComparison: "./../../mocks/roles/test-dev-role.json",
		},
		{
			name: "genRoleTestProd",
			args: args{
				filename:       "./../../mocks/prod-role.json",
				policies:       []string{"vh-test-prod"},
				prod:           true,
				projectID:      "15",
				lockProdClaims: true,
			},
			wantErr:            false,
			wantFileComparison: "./../../mocks/roles/test-prod-role.json",
		},
		{
			name: "genRoleTestProdNoLock",
			args: args{
				filename:       "./../../mocks/prod-role-no-lock.json",
				policies:       []string{"vh-test-prod"},
				prod:           true,
				projectID:      "15",
				lockProdClaims: false,
			},
			wantErr:            false,
			wantFileComparison: "./../../mocks/roles/test-prod-role-no-lock.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := genRole(tt.args.filename, tt.args.policies, tt.args.prod, tt.args.projectID, tt.args.lockProdClaims); (err != nil) != tt.wantErr {
				t.Errorf("genRole() error = %v, wantErr %v", err, tt.wantErr)
			}
			f1, err1 := ioutil.ReadFile(tt.args.filename)
			if err1 != nil {
				t.Errorf("could not read generated policy file: %s", err1)
			}

			f2, err1 := ioutil.ReadFile(tt.wantFileComparison)
			if err1 != nil {
				t.Errorf("could not read test role file: %s - %s", tt.wantFileComparison, err1)
			}
			if !bytes.Equal(f1, f2) {
				t.Errorf("role file did not result in expected output: \nGot: \n%v \nWanted: \n%v", string(f1), string(f2))
			}

			t.Cleanup(func() {
				err := os.RemoveAll(tt.args.filename)
				if err != nil {
					t.Errorf("unable to clean up generated role: %s -  %v", tt.args.filename, err)
				}
			})
		})
	}
}
