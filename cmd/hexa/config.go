// This code based on contributions from https://github.com/i2-open/i2goSignals with permission
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/sdk"
)

var ConfigFile = "config.json"

type ConfigData struct {
	Selected     string                      `json:"selected"`
	Integrations map[string]*sdk.Integration `json:"integrations"`
}

func (c *ConfigData) GetIntegration(alias string) *sdk.Integration {
	integration, exist := c.Integrations[alias]
	if exist {
		return integration
	}
	return nil
}

func (c *ConfigData) GetApplicationInfo(applicationAlias string) (*sdk.Integration, *policyprovider.ApplicationInfo) {
	for _, integration := range c.Integrations {
		app, exist := integration.Apps[applicationAlias]
		if exist {
			return integration, &app
		}
		// Check for match by object id
		for _, app := range integration.Apps {
			if app.ObjectID == applicationAlias {
				return integration, &app
			}
		}
	}
	return nil, nil
}

func (c *ConfigData) RemoveApplication(alias string) {
	integration, app := c.GetApplicationInfo(alias)
	if app != nil {
		delete(integration.Apps, alias)
	}
}

func (c *ConfigData) RemoveIntegration(alias string) {
	_, exist := c.Integrations[alias]
	if exist {
		delete(c.Integrations, alias)
	}
}

func (c *ConfigData) checkConfigPath(g *Globals) error {
	configPath := g.Config
	if configPath == "" {
		configPath = ".hexa/" + ConfigFile
		usr, err := user.Current()
		if err == nil {
			configPath = filepath.Join(usr.HomeDir, configPath)
		}
	}

	dirPath := filepath.Dir(configPath)
	i := len(dirPath)
	if dirPath[i-1:i-1] != "/" {
		dirPath = dirPath + "/"
	}
	baseFile := filepath.Base(configPath)
	if filepath.Ext(baseFile) == "" {
		dirPath = configPath
		baseFile = ConfigFile
	}

	_, err := os.Stat(dirPath)
	if os.IsNotExist(err) {

		// path/to/whatever does not exist
		err = os.Mkdir(dirPath, 0770)
		if err != nil {
			return err
		}
	}

	g.ConfigFile = configPath

	return nil
}

func (c *ConfigData) Load(g *Globals) error {
	// configFile := filepath.Join(g.Config, ConfigFile)

	if _, err := os.Stat(g.ConfigFile); os.IsNotExist(err) {
		return nil // No existing configuration
	}

	configBytes, err := os.ReadFile(g.ConfigFile)
	if err != nil {
		fmt.Println("Error reading configuration: " + err.Error())
		return nil
	}
	if len(configBytes) == 0 {
		return nil
	}
	err = json.Unmarshal(configBytes, c)
	if err != nil {
		fmt.Println("Error parsing stored configuration: " + err.Error())
	}
	return err
}

func (c *ConfigData) Save(g *Globals) error {

	out, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		return err
	}
	err = os.WriteFile(g.ConfigFile, out, 0660)
	if err != nil {
		fmt.Println("Error saving configuration: " + err.Error())
	}
	return err
}
