package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:     "aiscan",
	Short:   "All-in-one security scanner: Network + Web App + LLM",
	Long:    `aiscan is a 3-layer security scanner that covers Network (port scan), Web App (OWASP Top 10), and LLM (OWASP LLM Top 10) attack surfaces in a single CLI run.`,
	Version: version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
