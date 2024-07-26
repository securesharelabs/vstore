package cmd

import (
	"fmt"
	vfs "vstore/vfs"

	"github.com/spf13/cobra"
)

func init() {
	vstoreCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of vStore",
	Long:  `Print the version number of vStore.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("vStore v1.0 (vfs v%d)\n", vfs.AppVersion)
	},
}
