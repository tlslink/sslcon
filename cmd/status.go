package cmd

import (
    "fmt"
    "github.com/apieasy/gson"
    "github.com/spf13/cobra"
    "sslcon/rpc"
    "strings"
)

var status = &cobra.Command{
    Use:   "status",
    Short: "Get VPN connection information",
    Run: func(cmd *cobra.Command, args []string) {
        result := gson.New()
        err := rpcCall("status", nil, result, rpc.STATUS)
        if err != nil {
            after, _ := strings.CutPrefix(err.Error(), "jsonrpc2: code 1 message: ")
            fmt.Println(after)
        } else {
            result.Print()
        }
    },
}

func init() {
    rootCmd.AddCommand(status)
}
