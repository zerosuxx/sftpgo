// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//go:build !noportable

package service

import (
	"fmt"
	"math/rand"
	"slices"
	"strings"

	"github.com/rs/zerolog"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/config"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/ftpd"
	"github.com/drakkan/sftpgo/v2/internal/httpd"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/sftpd"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/webdavd"
)

// StartPortableMode starts the service in portable mode
func (s *Service) StartPortableMode(sftpdPort, ftpPort, webdavPort, httpPort int, enabledSSHCommands []string,
	ftpsCert, ftpsKey, webDavCert, webDavKey, httpsCert, httpsKey string) error {
	if s.PortableMode != 1 {
		return fmt.Errorf("service is not configured for portable mode")
	}
	err := config.LoadConfig(s.ConfigDir, s.ConfigFile)
	if err != nil {
		fmt.Printf("error loading configuration file: %v using defaults\n", err)
	}
	kmsConfig := config.GetKMSConfig()
	err = kmsConfig.Initialize()
	if err != nil {
		return err
	}
	printablePasswords := s.configurePortableUsers()
	dataProviderConf := config.GetProviderConf()
	dataProviderConf.Driver = dataprovider.MemoryDataProviderName
	dataProviderConf.Name = ""
	config.SetProviderConf(dataProviderConf)
	httpdConf := config.GetHTTPDConfig()
	for idx := range httpdConf.Bindings {
		httpdConf.Bindings[idx].Port = 0
	}
	config.SetHTTPDConfig(httpdConf)
	telemetryConf := config.GetTelemetryConfig()
	// telemetryConf.BindPort = 0
	config.SetTelemetryConfig(telemetryConf)

	configurePortableSFTPService(sftpdPort, enabledSSHCommands)
	configurePortableFTPService(ftpPort, ftpsCert, ftpsKey)
	configurePortableWebDAVService(webdavPort, webDavCert, webDavKey)
	configurePortableHTTPService(httpPort, httpsCert, httpsKey)

	err = s.Start()
	if err != nil {
		return err
	}
	if httpPort >= 0 {
		admin := &dataprovider.Admin{
			Username:    util.GenerateUniqueID(),
			Password:    util.GenerateUniqueID(),
			Status:      0,
			Permissions: []string{dataprovider.PermAdminAny},
		}
		if err := dataprovider.AddAdmin(admin, dataprovider.ActionExecutorSystem, "", ""); err != nil {
			return err
		}
	}

	usernames := zerolog.Arr()
	publicKeysList := zerolog.Arr()
	permissionsList := zerolog.Arr()
	filePatternsFilters := zerolog.Arr()
	for _, u := range s.PortableUsers {
		usernames.Str(u.Username)
		for _, pk := range u.PublicKeys {
			publicKeysList.Str(pk)
		}
		permissionsList.Interface(u.Permissions)
		filePatternsFilters.Interface(u.Filters.FilePatterns)
	}

	logger.
		GetLogger().
		Info().
		Array("users", usernames).
		Array("passwords", printablePasswords).
		Array("public_keys", publicKeysList).
		Array("directories", s.getPortableDirToServe()).
		Array("permissions", permissionsList).
		Array("file_patterns_filters", filePatternsFilters).
		Str("optional_info", strings.Trim(s.getServiceOptionalInfoString(), " ")).
		Msg("Portable mode ready")

	return nil
}

func (s *Service) getServiceOptionalInfoString() string {
	var info strings.Builder
	if config.GetSFTPDConfig().Bindings[0].IsValid() {
		info.WriteString(fmt.Sprintf("SFTP port: %v ", config.GetSFTPDConfig().Bindings[0].Port))
	}
	if config.GetFTPDConfig().Bindings[0].IsValid() {
		info.WriteString(fmt.Sprintf("FTP port: %v ", config.GetFTPDConfig().Bindings[0].Port))
	}
	if config.GetWebDAVDConfig().Bindings[0].IsValid() {
		scheme := "http"
		if config.GetWebDAVDConfig().CertificateFile != "" && config.GetWebDAVDConfig().CertificateKeyFile != "" {
			scheme = "https"
		}
		info.WriteString(fmt.Sprintf("WebDAV URL: %v://<your IP>:%v/ ", scheme, config.GetWebDAVDConfig().Bindings[0].Port))
	}
	if config.GetHTTPDConfig().Bindings[0].IsValid() {
		scheme := "http"
		if config.GetHTTPDConfig().CertificateFile != "" && config.GetHTTPDConfig().CertificateKeyFile != "" {
			scheme = "https"
		}
		info.WriteString(fmt.Sprintf("WebClient URL: %v://<your IP>:%v/ ", scheme, config.GetHTTPDConfig().Bindings[0].Port))
	}
	return info.String()
}

func (s *Service) getPortableDirToServe() *zerolog.Array {
	portableDirs := zerolog.Arr()
	for _, portableUser := range s.PortableUsers {
		switch portableUser.FsConfig.Provider {
		case sdk.S3FilesystemProvider:
			portableDirs.Str(portableUser.FsConfig.S3Config.KeyPrefix)
			break
		case sdk.GCSFilesystemProvider:
			portableDirs.Str(portableUser.FsConfig.GCSConfig.KeyPrefix)
			break
		case sdk.AzureBlobFilesystemProvider:
			portableDirs.Str(portableUser.FsConfig.AzBlobConfig.KeyPrefix)
			break
		case sdk.SFTPFilesystemProvider:
			portableDirs.Str(portableUser.FsConfig.SFTPConfig.Prefix)
			break
		case sdk.HTTPFilesystemProvider:
			portableDirs.Str("/")
			break
		default:
			portableDirs.Str(portableUser.HomeDir)
			break
		}
	}
	return portableDirs
}

// configures the portable user and return the printable password if any
func (s *Service) configurePortableUsers() *zerolog.Array {
	printablePasswords := zerolog.Arr()
	for id := range s.PortableUsers {
		portableUser := &s.PortableUsers[id]
		if portableUser.Username == "" {
			portableUser.Username = "user"
		}
		if portableUser.Password != "" {
			printablePasswords.Str("[redacted]")
		}
		if len(portableUser.PublicKeys) == 0 && portableUser.Password == "" {
			var b strings.Builder
			for i := 0; i < 16; i++ {
				b.WriteRune(chars[rand.Intn(len(chars))])
			}
			portableUser.Password = b.String()
			printablePasswords.Str(portableUser.Password)
		}
		portableUser.Filters.WebClient = []string{sdk.WebClientSharesDisabled, sdk.WebClientInfoChangeDisabled,
			sdk.WebClientPubKeyChangeDisabled, sdk.WebClientPasswordChangeDisabled, sdk.WebClientAPIKeyAuthChangeDisabled,
			sdk.WebClientMFADisabled,
		}
		s.configurePortableSecrets(portableUser)
	}

	return printablePasswords
}

func (s *Service) configurePortableSecrets(portableUser *dataprovider.User) {
	// we created the user before to initialize the KMS so we need to create the secret here
	switch portableUser.FsConfig.Provider {
	case sdk.S3FilesystemProvider:
		payload := portableUser.FsConfig.S3Config.AccessSecret.GetPayload()
		portableUser.FsConfig.S3Config.AccessSecret = getSecretFromString(payload)
	case sdk.GCSFilesystemProvider:
		payload := portableUser.FsConfig.GCSConfig.Credentials.GetPayload()
		portableUser.FsConfig.GCSConfig.Credentials = getSecretFromString(payload)
	case sdk.AzureBlobFilesystemProvider:
		payload := portableUser.FsConfig.AzBlobConfig.AccountKey.GetPayload()
		portableUser.FsConfig.AzBlobConfig.AccountKey = getSecretFromString(payload)
		payload = portableUser.FsConfig.AzBlobConfig.SASURL.GetPayload()
		portableUser.FsConfig.AzBlobConfig.SASURL = getSecretFromString(payload)
	case sdk.CryptedFilesystemProvider:
		payload := portableUser.FsConfig.CryptConfig.Passphrase.GetPayload()
		portableUser.FsConfig.CryptConfig.Passphrase = getSecretFromString(payload)
	case sdk.SFTPFilesystemProvider:
		payload := portableUser.FsConfig.SFTPConfig.Password.GetPayload()
		portableUser.FsConfig.SFTPConfig.Password = getSecretFromString(payload)
		payload = portableUser.FsConfig.SFTPConfig.PrivateKey.GetPayload()
		portableUser.FsConfig.SFTPConfig.PrivateKey = getSecretFromString(payload)
		payload = portableUser.FsConfig.SFTPConfig.KeyPassphrase.GetPayload()
		portableUser.FsConfig.SFTPConfig.KeyPassphrase = getSecretFromString(payload)
	case sdk.HTTPFilesystemProvider:
		payload := portableUser.FsConfig.HTTPConfig.Password.GetPayload()
		portableUser.FsConfig.HTTPConfig.Password = getSecretFromString(payload)
		payload = portableUser.FsConfig.HTTPConfig.APIKey.GetPayload()
		portableUser.FsConfig.HTTPConfig.APIKey = getSecretFromString(payload)
	default:
	}
}

func getSecretFromString(payload string) *kms.Secret {
	if payload != "" {
		return kms.NewPlainSecret(payload)
	}
	return kms.NewEmptySecret()
}

func configurePortableSFTPService(port int, enabledSSHCommands []string) {
	sftpdConf := config.GetSFTPDConfig()
	if len(sftpdConf.Bindings) == 0 {
		sftpdConf.Bindings = append(sftpdConf.Bindings, sftpd.Binding{})
	}
	if port > 0 {
		sftpdConf.Bindings[0].Port = port
	} else if port == 0 {
		// dynamic ports starts from 49152
		sftpdConf.Bindings[0].Port = 49152 + rand.Intn(15000)
	} else {
		sftpdConf.Bindings[0].Port = 0
	}
	if slices.Contains(enabledSSHCommands, "*") {
		sftpdConf.EnabledSSHCommands = sftpd.GetSupportedSSHCommands()
	} else {
		sftpdConf.EnabledSSHCommands = enabledSSHCommands
	}
	config.SetSFTPDConfig(sftpdConf)
}

func configurePortableFTPService(port int, cert, key string) {
	ftpConf := config.GetFTPDConfig()
	if len(ftpConf.Bindings) == 0 {
		ftpConf.Bindings = append(ftpConf.Bindings, ftpd.Binding{})
	}
	if port > 0 {
		ftpConf.Bindings[0].Port = port
	} else if port == 0 {
		ftpConf.Bindings[0].Port = 49152 + rand.Intn(15000)
	} else {
		ftpConf.Bindings[0].Port = 0
	}
	ftpConf.Bindings[0].CertificateFile = cert
	ftpConf.Bindings[0].CertificateKeyFile = key
	config.SetFTPDConfig(ftpConf)
}

func configurePortableWebDAVService(port int, cert, key string) {
	webDavConf := config.GetWebDAVDConfig()
	if len(webDavConf.Bindings) == 0 {
		webDavConf.Bindings = append(webDavConf.Bindings, webdavd.Binding{})
	}
	if port > 0 {
		webDavConf.Bindings[0].Port = port
	} else if port == 0 {
		webDavConf.Bindings[0].Port = 49152 + rand.Intn(15000)
	} else {
		webDavConf.Bindings[0].Port = 0
	}
	webDavConf.Bindings[0].CertificateFile = cert
	webDavConf.Bindings[0].CertificateKeyFile = key
	if cert != "" && key != "" {
		webDavConf.Bindings[0].EnableHTTPS = true
	}
	config.SetWebDAVDConfig(webDavConf)
}

func configurePortableHTTPService(port int, cert, key string) {
	httpdConf := config.GetHTTPDConfig()
	if len(httpdConf.Bindings) == 0 {
		httpdConf.Bindings = append(httpdConf.Bindings, httpd.Binding{})
	}
	if port > 0 {
		httpdConf.Bindings[0].Port = port
	} else if port == 0 {
		httpdConf.Bindings[0].Port = 49152 + rand.Intn(15000)
	} else {
		httpdConf.Bindings[0].Port = 0
	}
	httpdConf.Bindings[0].CertificateFile = cert
	httpdConf.Bindings[0].CertificateKeyFile = key
	if cert != "" && key != "" {
		httpdConf.Bindings[0].EnableHTTPS = true
	}
	httpdConf.Bindings[0].EnableWebAdmin = false
	httpdConf.Bindings[0].EnableWebClient = true
	httpdConf.Bindings[0].EnableRESTAPI = false
	httpdConf.Bindings[0].RenderOpenAPI = false
	config.SetHTTPDConfig(httpdConf)
}
