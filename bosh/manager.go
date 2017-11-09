package bosh

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	yaml "gopkg.in/yaml.v2"

	"github.com/cloudfoundry/bosh-bootloader/storage"
)

var (
	osSetenv   = os.Setenv
	osUnsetenv = os.Unsetenv
)

type Manager struct {
	executor    executor
	logger      logger
	socks5Proxy socks5Proxy
	stateStore  stateStore
}

type directorVars struct {
	address        string
	username       string
	password       string
	sslCA          string
	sslCertificate string
	sslPrivateKey  string
}

type sharedDeploymentVarsYAML struct {
	InternalCIDR string    `json:"internal_cidr" yaml:"internal_cidr,omitempty"`
	InternalGW   string    `yaml:"internal_gw,omitempty"`
	InternalIP   string    `yaml:"internal_ip,omitempty"`
	DirectorName string    `yaml:"director_name,omitempty"`
	ExternalIP   string    `json:"bosh_director_external_ip" yaml:"external_ip,omitempty"`
	PrivateKey   string    `json:"bosh_vms_private_key" yaml:"private_key,flow,omitempty"`
	AWSYAML      AWSYAML   `yaml:",inline"`
	GCPYAML      GCPYAML   `yaml:",inline"`
	AzureYAML    AzureYAML `yaml:",inline"`
}

type AWSYAML struct {
	AZ                            string   `json:"bosh_subnet_availability_zone" yaml:"az,omitempty"`
	SubnetID                      string   `json:"bosh_subnet_id" yaml:"subnet_id,omitempty"`
	AccessKeyID                   string   `yaml:"access_key_id,omitempty"`
	SecretAccessKey               string   `yaml:"secret_access_key,omitempty"`
	IAMInstanceProfile            string   `json:"bosh_iam_instance_profile" yaml:"iam_instance_profile,omitempty"`
	DefaultKeyName                string   `json:"bosh_vms_key_name" yaml:"default_key_name,omitempty"`
	DirectorDefaultSecurityGroups []string `json:"bosh_security_group" yaml:"default_security_groups,omitempty"`
	JumpboxDefaultSecurityGroups  []string `json:"jumpbox_security_group" yaml:"default_security_groups,omitempty"`
	Region                        string   `yaml:"region,omitempty"`
	KMSKeyARN                     string   `json:"kms_key_arn" yaml:"kms_key_arn,omitempty"`
}

type GCPYAML struct {
	Zone           string   `yaml:"zone,omitempty"`
	Network        string   `json:"network_name" yaml:"network,omitempty"`
	Subnetwork     string   `json:"subnetwork_name" yaml:"subnetwork,omitempty"`
	DirectorTags   []string `json:"director_tags" yaml:"tags,omitempty"`
	JumpboxTags    []string `json:"jumpbox_tags" yaml:"tags,omitempty"`
	ProjectID      string   `yaml:"project_id,omitempty"`
	CredentialJSON string   `yaml:"gcp_credentials_json,omitempty"`
}

type AzureYAML struct {
	VNetName              string `json:"bosh_network_name" yaml:"vnet_name,omitempty"`
	SubnetName            string `json:"bosh_subnet_name" yaml:"subnet_name,omitempty"`
	SubscriptionID        string `yaml:"subscription_id,omitempty"`
	TenantID              string `yaml:"tenant_id,omitempty"`
	ClientID              string `yaml:"client_id,omitempty"`
	ClientSecret          string `yaml:"client_secret,omitempty"`
	ResourceGroupName     string `json:"bosh_resource_group_name" yaml:"resource_group_name,omitempty"`
	StorageAccountName    string `json:"bosh_storage_account_name" yaml:"storage_account_name,omitempty"`
	DirectorSecurityGroup string `json:"bosh_default_security_group" yaml:"default_security_group,omitempty"`
	PublicKey             string `yaml:"public_key,flow,omitempty"`
}

type executor interface {
	DirectorCreateEnvArgs(InterpolateInput) error
	JumpboxCreateEnvArgs(InterpolateInput) error
	CreateEnv(CreateEnvInput) (string, error)
	DeleteEnv(DeleteEnvInput) error
	Version() (string, error)
}

type logger interface {
	Step(string, ...interface{})
	Println(string)
}

type socks5Proxy interface {
	Start(string, string) error
	Addr() (string, error)
}

type stateStore interface {
	GetStateDir() string
	GetVarsDir() (string, error)
	GetDirectorDeploymentDir() (string, error)
	GetJumpboxDeploymentDir() (string, error)
}

func NewManager(executor executor, logger logger, socks5Proxy socks5Proxy, stateStore stateStore) *Manager {
	return &Manager{
		executor:    executor,
		logger:      logger,
		socks5Proxy: socks5Proxy,
		stateStore:  stateStore,
	}
}

func (m *Manager) Version() (string, error) {
	version, err := m.executor.Version()
	switch err.(type) {
	case BOSHVersionError:
		m.logger.Println("warning: BOSH version could not be parsed")
	}
	return version, err
}

func (m *Manager) InitializeJumpbox(state storage.State) error {
	varsDir, err := m.stateStore.GetVarsDir()
	if err != nil {
		return fmt.Errorf("Get vars dir: %s", err)
	}

	stateDir := m.stateStore.GetStateDir()

	deploymentDir, err := m.stateStore.GetJumpboxDeploymentDir()
	if err != nil {
		return fmt.Errorf("Get deployment dir: %s", err)
	}

	iaasInputs := InterpolateInput{
		DeploymentDir: deploymentDir,
		StateDir:      stateDir,
		VarsDir:       varsDir,
		IAAS:          state.IAAS,
		Variables:     state.Jumpbox.Variables,
		BOSHState:     state.Jumpbox.State,
	}

	err = m.executor.JumpboxCreateEnvArgs(iaasInputs)
	if err != nil {
		return fmt.Errorf("Jumpbox interpolate: %s", err)
	}

	return nil
}

func (m *Manager) CreateJumpbox(state storage.State, terraformOutputs []byte) (storage.State, error) {
	m.logger.Step("creating jumpbox")

	varsDir, err := m.stateStore.GetVarsDir()
	if err != nil {
		return storage.State{}, fmt.Errorf("Get vars dir: %s", err)
	}

	stateDir := m.stateStore.GetStateDir()
	osUnsetenv("BOSH_ALL_PROXY")

	variables, err := m.executor.CreateEnv(CreateEnvInput{
		Deployment:     "jumpbox",
		VarsDir:        varsDir,
		StateDir:       stateDir,
		DeploymentVars: m.GetJumpboxDeploymentVars(state, terraformOutputs),
	})
	switch err.(type) {
	case CreateEnvError:
		ceErr := err.(CreateEnvError)
		state.Jumpbox = storage.Jumpbox{
			Variables: variables,
			State:     ceErr.BOSHState(),
		}
		return storage.State{}, fmt.Errorf("Create jumpbox env: %s", NewManagerCreateError(state, err))
	case error:
		return storage.State{}, fmt.Errorf("Create jumpbox env: %s", err)
	}
	m.logger.Step("created jumpbox")

	deploymentVars := unmarshalTerraformOutputs(terraformOutputs)
	state.Jumpbox = storage.Jumpbox{
		Variables: variables,
		URL:       fmt.Sprintf("%s:22", deploymentVars.ExternalIP),
	}

	m.logger.Step("starting socks5 proxy to jumpbox")
	jumpboxPrivateKey, err := getJumpboxPrivateKey(variables)
	if err != nil {
		return storage.State{}, fmt.Errorf("jumpbox key: %s", err)
	}

	err = m.socks5Proxy.Start(jumpboxPrivateKey, state.Jumpbox.URL)
	if err != nil {
		return storage.State{}, fmt.Errorf("Start proxy: %s", err)
	}

	addr, err := m.socks5Proxy.Addr()
	if err != nil {
		return storage.State{}, fmt.Errorf("Get proxy address: %s", err)
	}
	osSetenv("BOSH_ALL_PROXY", fmt.Sprintf("socks5://%s", addr))

	m.logger.Step("started proxy")
	return state, nil
}

func (m *Manager) InitializeDirector(state storage.State) error {
	varsDir, err := m.stateStore.GetVarsDir()
	if err != nil {
		return fmt.Errorf("Get vars dir: %s", err)
	}

	stateDir := m.stateStore.GetStateDir()

	directorDeploymentDir, err := m.stateStore.GetDirectorDeploymentDir()
	if err != nil {
		return fmt.Errorf("Get deployment dir: %s", err)
	}

	iaasInputs := InterpolateInput{
		DeploymentDir: directorDeploymentDir,
		StateDir:      stateDir,
		VarsDir:       varsDir,
		IAAS:          state.IAAS,
		Variables:     state.BOSH.Variables,
		OpsFile:       state.BOSH.UserOpsFile,
		BOSHState:     state.BOSH.State,
	}

	err = m.executor.DirectorCreateEnvArgs(iaasInputs)
	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) CreateDirector(state storage.State, terraformOutputs []byte) (storage.State, error) {
	m.logger.Step("creating bosh director")

	varsDir, err := m.stateStore.GetVarsDir()
	if err != nil {
		return storage.State{}, fmt.Errorf("Get vars dir: %s", err)
	}

	stateDir := m.stateStore.GetStateDir()

	variables, err := m.executor.CreateEnv(CreateEnvInput{
		Deployment:     "director",
		StateDir:       stateDir,
		VarsDir:        varsDir,
		DeploymentVars: m.GetDirectorDeploymentVars(state, terraformOutputs),
	})

	switch err.(type) {
	case CreateEnvError:
		ceErr := err.(CreateEnvError)
		state.BOSH = storage.BOSH{
			Variables: variables,
			State:     ceErr.BOSHState(),
		}
		return storage.State{}, NewManagerCreateError(state, err)
	case error:
		return storage.State{}, fmt.Errorf("Create director env: %s", err)
	}

	directorVars := getDirectorVars(variables)

	state.BOSH = storage.BOSH{
		DirectorName:           fmt.Sprintf("bosh-%s", state.EnvID),
		DirectorAddress:        directorVars.address,
		DirectorUsername:       directorVars.username,
		DirectorPassword:       directorVars.password,
		DirectorSSLCA:          directorVars.sslCA,
		DirectorSSLCertificate: directorVars.sslCertificate,
		DirectorSSLPrivateKey:  directorVars.sslPrivateKey,
		Variables:              variables,
		UserOpsFile:            state.BOSH.UserOpsFile,
	}

	m.logger.Step("created bosh director")
	return state, nil
}

func (m *Manager) DeleteDirector(state storage.State) error {
	varsDir, err := m.stateStore.GetVarsDir()
	if err != nil {
		return fmt.Errorf("Get vars dir: %s", err)
	}

	stateDir := m.stateStore.GetStateDir()

	deploymentDir, err := m.stateStore.GetDirectorDeploymentDir()
	if err != nil {
		return fmt.Errorf("Get deployment dir: %s", err)
	}

	iaasInputs := InterpolateInput{
		DeploymentDir: deploymentDir,
		StateDir:      stateDir,
		VarsDir:       varsDir,
		IAAS:          state.IAAS,
		BOSHState:     state.BOSH.State,
		Variables:     state.BOSH.Variables,
		OpsFile:       state.BOSH.UserOpsFile,
	}

	jumpboxPrivateKey, err := getJumpboxPrivateKey(state.Jumpbox.Variables)
	if err != nil {
		return fmt.Errorf("Delete bosh director: %s", err)
	}

	err = m.socks5Proxy.Start(jumpboxPrivateKey, state.Jumpbox.URL)
	if err != nil {
		return fmt.Errorf("Start socks5 proxy: %s", err)
	}

	addr, err := m.socks5Proxy.Addr()
	if err != nil {
		return fmt.Errorf("Get proxy address: %s", err)
	}
	osSetenv("BOSH_ALL_PROXY", fmt.Sprintf("socks5://%s", addr))

	err = m.executor.DirectorCreateEnvArgs(iaasInputs)
	if err != nil {
		return err
	}

	err = m.executor.DeleteEnv(DeleteEnvInput{
		Deployment: "director",
		VarsDir:    varsDir,
		StateDir:   stateDir,
	})
	switch err.(type) {
	case DeleteEnvError:
		deErr := err.(DeleteEnvError)
		state.BOSH.State = deErr.BOSHState()
		return NewManagerDeleteError(state, err)
	case error:
		return fmt.Errorf("Delete director env: %s", err)
	}

	return nil
}

func (m *Manager) DeleteJumpbox(state storage.State) error {
	m.logger.Step("destroying jumpbox")

	varsDir, err := m.stateStore.GetVarsDir()
	if err != nil {
		return fmt.Errorf("Get vars dir: %s", err)
	}

	stateDir := m.stateStore.GetStateDir()

	deploymentDir, err := m.stateStore.GetJumpboxDeploymentDir()
	if err != nil {
		return fmt.Errorf("Get deployment dir: %s", err)
	}

	iaasInputs := InterpolateInput{
		DeploymentDir: deploymentDir,
		StateDir:      stateDir,
		VarsDir:       varsDir,
		IAAS:          state.IAAS,
		Variables:     state.Jumpbox.Variables,
	}

	err = m.executor.JumpboxCreateEnvArgs(iaasInputs)
	if err != nil {
		return err
	}

	err = m.executor.DeleteEnv(DeleteEnvInput{
		Deployment: "jumpbox",
		StateDir:   stateDir,
		VarsDir:    varsDir,
	})
	switch err.(type) {
	case DeleteEnvError:
		deErr := err.(DeleteEnvError)
		state.Jumpbox.State = deErr.BOSHState()
		return NewManagerDeleteError(state, err)
	case error:
		return fmt.Errorf("Delete jumpbox env: %s", err)
	}

	return nil
}

func unmarshalTerraformOutputs(terraformOutputs []byte) sharedDeploymentVarsYAML {
	var deploymentVars sharedDeploymentVarsYAML
	err := json.Unmarshal(terraformOutputs, &deploymentVars)
	if err != nil {
		panic(err)
	}
	return deploymentVars
}

func (m *Manager) GetJumpboxDeploymentVars(state storage.State, terraformOutputs []byte) string {
	deploymentVars := unmarshalTerraformOutputs(terraformOutputs)
	internalCIDR := deploymentVars.InternalCIDR

	parsedInternalCIDR, err := ParseCIDRBlock(internalCIDR)
	if err != nil {
		internalCIDR = "10.0.0.0/24"
		parsedInternalCIDR, _ = ParseCIDRBlock(internalCIDR)
	}

	deploymentVars.InternalGW = parsedInternalCIDR.GetNthIP(1).String()
	deploymentVars.InternalIP = parsedInternalCIDR.GetNthIP(5).String()
	deploymentVars.DirectorName = fmt.Sprintf("bosh-%s", state.EnvID)

	switch state.IAAS {
	case "gcp":
		deploymentVars.GCPYAML.Zone = state.GCP.Zone
		deploymentVars.GCPYAML.ProjectID = state.GCP.ProjectID
		deploymentVars.GCPYAML.CredentialJSON = state.GCP.ServiceAccountKey
	case "aws":
		deploymentVars.AWSYAML.AccessKeyID = state.AWS.AccessKeyID
		deploymentVars.AWSYAML.SecretAccessKey = state.AWS.SecretAccessKey
		deploymentVars.AWSYAML.Region = state.AWS.Region
	case "azure":
		deploymentVars.AzureYAML.SubscriptionID = state.Azure.SubscriptionID
		deploymentVars.AzureYAML.TenantID = state.Azure.TenantID
		deploymentVars.AzureYAML.ClientID = state.Azure.ClientID
		deploymentVars.AzureYAML.ClientSecret = state.Azure.ClientSecret
	}

	content, err := yaml.Marshal(deploymentVars)
	if err != nil {
		panic(err)
	}
	return string(content)
}

func mustMarshal(yamlStruct interface{}) []byte {
	yamlBytes, err := yaml.Marshal(yamlStruct)
	if err != nil {
		// this should never happen since we are constructing the YAML to be marshaled
		panic("bosh manager: marshal yaml: unexpected error")
	}
	return yamlBytes
}

func (m *Manager) GetDirectorDeploymentVars(state storage.State, terraformOutputs []byte) string {
	deploymentVars := unmarshalTerraformOutputs(terraformOutputs)
	internalCIDR := deploymentVars.InternalCIDR

	parsedInternalCIDR, err := ParseCIDRBlock(internalCIDR)
	if err != nil {
		internalCIDR = "10.0.0.0/24"
		parsedInternalCIDR, _ = ParseCIDRBlock(internalCIDR)
	}

	// vars := sharedDeploymentVarsYAML{
	// deploymentVars.InternalCIDR = internalCIDR
	deploymentVars.InternalGW = parsedInternalCIDR.GetNthIP(1).String()
	deploymentVars.InternalIP = parsedInternalCIDR.GetNthIP(6).String()
	deploymentVars.DirectorName = fmt.Sprintf("bosh-%s", state.EnvID)
	// 	ExternalIP:   terraformOutputs.GetString("bosh_director_external_ip"),
	// }

	switch state.IAAS {
	case "gcp":
		deploymentVars.GCPYAML.Zone = state.GCP.Zone
		deploymentVars.GCPYAML.ProjectID = state.GCP.ProjectID
		deploymentVars.GCPYAML.CredentialJSON = state.GCP.ServiceAccountKey
		// Network:        terraformOutputs.GetString("network_name"),
		// Subnetwork:     terraformOutputs.GetString("subnetwork_name"),
		// Tags:           terraformOutputs.GetStringSlice("director_tags"),
	case "aws":
		// AZ:                    terraformOutputs.GetString("bosh_subnet_availability_zone"),
		// SubnetID:              terraformOutputs.GetString("bosh_subnet_id"),
		deploymentVars.AWSYAML.AccessKeyID = state.AWS.AccessKeyID
		deploymentVars.AWSYAML.SecretAccessKey = state.AWS.SecretAccessKey
		// IAMInstanceProfile:    terraformOutputs.GetString("bosh_iam_instance_profile"),
		// DefaultKeyName:        terraformOutputs.GetString("bosh_vms_key_name"),
		// DefaultSecurityGroups: terraformOutputs.GetStringSlice("bosh_security_group"),
		deploymentVars.AWSYAML.Region = state.AWS.Region
		// KMSKeyARN:             terraformOutputs.GetString("kms_key_arn"),
		// deploymentVars.PrivateKey = terraformOutputs.GetString("bosh_vms_private_key")
	case "azure":
		// VNetName:             terraformOutputs.GetString("bosh_network_name"),
		// SubnetName:           terraformOutputs.GetString("bosh_subnet_name"),
		deploymentVars.AzureYAML.SubscriptionID = state.Azure.SubscriptionID
		deploymentVars.AzureYAML.TenantID = state.Azure.TenantID
		deploymentVars.AzureYAML.ClientID = state.Azure.ClientID
		deploymentVars.AzureYAML.ClientSecret = state.Azure.ClientSecret
		// ResourceGroupName:    terraformOutputs.GetString("bosh_resource_group_name"),
		// StorageAccountName:   terraformOutputs.GetString("bosh_storage_account_name"),
		// DefaultSecurityGroup: terraformOutputs.GetString("bosh_default_security_group"),
	}

	content, err := yaml.Marshal(deploymentVars)
	if err != nil {
		panic(err)
	}
	return string(content)
}

func getJumpboxPrivateKey(v string) (string, error) {
	var vars struct {
		JumpboxSSH struct {
			PrivateKey string `yaml:"private_key"`
		} `yaml:"jumpbox_ssh"`
	}

	err := yaml.Unmarshal([]byte(v), &vars)
	if err != nil {
		return "", err
	}
	if vars.JumpboxSSH.PrivateKey == "" {
		return "", errors.New("cannot start proxy due to missing jumpbox private key")
	}

	return vars.JumpboxSSH.PrivateKey, nil
}

func getDirectorVars(v string) directorVars {
	var vars struct {
		AdminPassword string `yaml:"admin_password"`
		DirectorSSL   struct {
			CA          string `yaml:"ca"`
			Certificate string `yaml:"certificate"`
			PrivateKey  string `yaml:"private_key"`
		} `yaml:"director_ssl"`
	}

	err := yaml.Unmarshal([]byte(v), &vars)
	if err != nil {
		panic(err) // can't happen
	}

	return directorVars{
		address:        "https://10.0.0.6:25555",
		username:       "admin",
		password:       vars.AdminPassword,
		sslCA:          vars.DirectorSSL.CA,
		sslCertificate: vars.DirectorSSL.Certificate,
		sslPrivateKey:  vars.DirectorSSL.PrivateKey,
	}
}
