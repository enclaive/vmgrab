package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the CLI configuration
type Config struct {
	VMs    VMConfig     `yaml:"vms"`
	Search SearchConfig `yaml:"search_patterns"`
}

// VMConfig defines VM configurations
type VMConfig struct {
	Standard     VMInfo `yaml:"standard"`
	Confidential VMInfo `yaml:"confidential"`
}

// VMInfo contains VM details
type VMInfo struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// SearchConfig defines search patterns
type SearchConfig []SearchPattern

// SearchPattern represents a search pattern
type SearchPattern struct {
	Name     string   `yaml:"name"`
	Pattern  string   `yaml:"pattern"`
	Examples []string `yaml:"examples,omitempty"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		VMs: VMConfig{
			Standard: VMInfo{
				Name:        "neo4j-vm1",
				Description: "Standard VM (no encryption)",
			},
			Confidential: VMInfo{
				Name:        "neo4j-cvm",
				Description: "Confidential VM (SEV-SNP)",
			},
		},
		Search: SearchConfig{
			{
				Name:     "NHS Numbers",
				Pattern:  `\d{3}-\d{2}-\d{4}`,
				Examples: []string{"117-66-8129", "991-70-5333"},
			},
			{
				Name:    "Emails",
				Pattern: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			},
			{
				Name:    "Person Names",
				Pattern: `Person\(.*name:"[^"]+"`,
			},
		},
	}
}

// Load loads configuration from file
func Load(path string) (*Config, error) {
	// If no path specified, try default locations
	if path == "" {
		path = findConfigFile()
	}

	// If still no config found, return defaults
	if path == "" {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// Save saves configuration to file
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.VMs.Standard.Name == "" {
		return fmt.Errorf("standard VM name is required")
	}
	if c.VMs.Confidential.Name == "" {
		return fmt.Errorf("confidential VM name is required")
	}
	return nil
}

// findConfigFile searches for config file in common locations
func findConfigFile() string {
	// Search order:
	// 1. ./.vmgrab.yaml
	// 2. ~/.vmgrab.yaml
	// 3. ~/.config/vmgrab/config.yaml

	locations := []string{
		".vmgrab.yaml",
		filepath.Join(os.Getenv("HOME"), ".vmgrab.yaml"),
		filepath.Join(os.Getenv("HOME"), ".config", "vmgrab", "config.yaml"),
	}

	for _, loc := range locations {
		if _, err := os.Stat(loc); err == nil {
			return loc
		}
	}

	return ""
}

// GetConfigPath returns the path where config should be saved
func GetConfigPath() string {
	// Prefer current directory
	return ".vmgrab.yaml"
}

// ExampleConfig returns an example configuration as YAML string
func ExampleConfig() string {
	cfg := DefaultConfig()
	data, _ := yaml.Marshal(cfg)

	header := `# KVM Memory Dump Tool Configuration
#
# This file configures the vmgrab CLI tool for your environment.
# Copy this to .vmgrab.yaml and customize for your setup.
#
# Configuration priority:
#   1. CLI flags (--host, --standard-vm, etc.)
#   2. This config file
#   3. Built-in defaults

`
	return header + string(data)
}
