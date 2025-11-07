package cmd

import (
	"fmt"
	"os"

	"github.com/enclaive/vmgrab/pkg/config"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
	Long:  "Create, view, and validate vmgrab configuration",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration file",
	Long:  "Create a new .vmgrab.yaml configuration file with defaults",
	RunE:  runConfigInit,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Long:  "Display the active configuration (from file or defaults)",
	RunE:  runConfigShow,
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration file",
	Long:  "Check if the configuration file is valid",
	RunE:  runConfigValidate,
}

var (
	configForce bool
)

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configValidateCmd)

	configInitCmd.Flags().BoolVarP(&configForce, "force", "f", false, "Overwrite existing config file")
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	configPath := config.GetConfigPath()

	// Check if file exists
	if _, err := os.Stat(configPath); err == nil && !configForce {
		return fmt.Errorf("config file already exists: %s (use --force to overwrite)", configPath)
	}

	// Create default config
	cfg := config.DefaultConfig()

	// Save to file
	if err := cfg.Save(configPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	color.Green("✅ Configuration file created: %s", configPath)
	fmt.Println()
	color.Cyan("Next steps:")
	fmt.Printf("  1. Edit the file: %s\n", color.HiWhiteString("nano %s", configPath))
	fmt.Printf("  2. Customize VM names and search patterns\n")
	fmt.Printf("  3. Validate: %s\n", color.HiWhiteString("vmgrab config validate"))
	fmt.Printf("  4. Run demo: %s\n", color.HiWhiteString("vmgrab demo"))
	fmt.Println()

	return nil
}

func runConfigShow(cmd *cobra.Command, args []string) error {
	// Load config
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Print header
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Println("\n🔧 Current Configuration")
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println()

	// Determine source
	configPath := ""
	for _, loc := range []string{".vmgrab.yaml", os.Getenv("HOME") + "/.vmgrab.yaml"} {
		if _, err := os.Stat(loc); err == nil {
			configPath = loc
			break
		}
	}

	if configPath != "" {
		fmt.Printf("📂 Source: %s\n", color.CyanString(configPath))
	} else {
		fmt.Printf("📂 Source: %s\n", color.YellowString("Built-in defaults (no config file found)"))
	}
	fmt.Println()

	// Marshal to YAML for pretty printing
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	fmt.Println(color.HiWhiteString(string(data)))

	// Print info
	fmt.Println(color.HiBlackString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Println()
	color.HiBlack("💡 Tip: Create a config file with 'vmgrab config init'")
	fmt.Println()

	return nil
}

func runConfigValidate(cmd *cobra.Command, args []string) error {
	// Try to find config file
	configPath := ""
	for _, loc := range []string{".vmgrab.yaml", os.Getenv("HOME") + "/.vmgrab.yaml"} {
		if _, err := os.Stat(loc); err == nil {
			configPath = loc
			break
		}
	}

	if configPath == "" {
		color.Yellow("⚠️  No config file found")
		fmt.Println()
		fmt.Println("Create one with:", color.CyanString("vmgrab config init"))
		return nil
	}

	// Load and validate
	cfg, err := config.Load(configPath)
	if err != nil {
		color.Red("❌ Config file is invalid:")
		fmt.Printf("   %v\n", err)
		return nil
	}

	if err := cfg.Validate(); err != nil {
		color.Red("❌ Validation failed:")
		fmt.Printf("   %v\n", err)
		return nil
	}

	// Success
	color.Green("✅ Configuration is valid: %s", configPath)
	fmt.Println()

	// Show summary
	color.Cyan("📋 Configuration summary:")
	fmt.Printf("   Host:         %s\n", color.HiWhiteString("%s@%s", cfg.User, cfg.Host))
	fmt.Printf("   Standard VM:  %s\n", color.HiWhiteString(cfg.VMs.Standard.Name))
	fmt.Printf("   Confident VM: %s\n", color.HiWhiteString(cfg.VMs.Confidential.Name))
	fmt.Printf("   Patterns:     %s\n", color.HiWhiteString("%d defined", len(cfg.Search)))
	fmt.Println()

	return nil
}
