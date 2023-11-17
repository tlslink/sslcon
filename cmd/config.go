package cmd

import (
    "fmt"
    "github.com/spf13/cobra"
    "github.com/tlslink/simplejson"
    "os"
    "sslcon/rpc"
    "strings"
)

var (
    logLevel string
    logPath  string
)

var config = &cobra.Command{
    Use:   "config",
    Short: "Set up VPN service",
    Run: func(cmd *cobra.Command, args []string) {

        params := make(map[string]string)
        params["log_level"] = logLevel
        params["log_path"] = logPath

        result := simplejson.New()
        err := rpcCall("config", params, result, rpc.CONFIG)
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
    rootCmd.AddCommand(config)

    config.Flags().StringVarP(&logLevel, "log_level", "l", "info", "Set the log level")
    config.Flags().StringVarP(&logPath, "log_path", "d", os.TempDir(), "Set the log directory")
}
