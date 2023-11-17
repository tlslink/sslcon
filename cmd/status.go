package cmd

import (
    "fmt"
    "github.com/spf13/cobra"
    "github.com/tlslink/simplejson"
    "sslcon/rpc"
    "strings"
)

var status = &cobra.Command{
    Use:   "status",
    Short: "Get VPN connection information",
    Run: func(cmd *cobra.Command, args []string) {
        result := simplejson.New()
        err := rpcCall("status", nil, result, rpc.STATUS)
        if err != nil {
            after, _ := strings.CutPrefix(err.Error(), "jsonrpc2: code 1 message: ")
            fmt.Println(after)
        } else {
            pretty, _ := result.EncodePretty()
            fmt.Println(string(pretty))
        }
    },
}

func init() {
    rootCmd.AddCommand(status)
}
