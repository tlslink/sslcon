package cmd

import (
	"fmt"
	"strings"

	"github.com/apieasy/gson"
	"github.com/spf13/cobra"
	"sslcon/rpc"
)

var disconnect = &cobra.Command{
	Use:   "disconnect",
	Short: "Disconnect from the VPN server",
	Run: func(cmd *cobra.Command, args []string) {
		result := gson.New()
		err := rpcCall("disconnect", nil, result, rpc.DISCONNECT)
		if err != nil {
			after, _ := strings.CutPrefix(err.Error(), "jsonrpc2: code 1 message: ")
			fmt.Println(after)
		} else {
			result.Print()
		}
	},
}

func init() {
	rootCmd.AddCommand(disconnect)
}
