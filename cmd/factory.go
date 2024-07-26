package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	vstoreCmd.AddCommand(factoryCmd)
}

var factoryCmd = &cobra.Command{
	Use:   "factory",
	Short: "Use the vstore transaction factory",
	Long:  `Use the vstore transaction factory to create digitally signed datasets.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Using Factory is cool!")
	},
}
