package cmd

import (
    "fmt"
    "github.com/apieasy/gson"
    "github.com/spf13/cobra"
    "golang.org/x/crypto/ssh/terminal"
    "os"
    "sslcon/rpc"
    "strings"
)

var (
    host     string
    username string
    password string
    group    string
    secret   string

    logLevel string
    logPath  string
)

var connect = &cobra.Command{
    Use:   "connect",
    Short: "Connect to the VPN server",
    // Args:  cobra.MinimumNArgs(1), // 至少1个非选项参数
    Run: func(cmd *cobra.Command, args []string) {
        if host == "" || username == "" {
            cmd.Help()
        } else {
            if password == "" {
                fmt.Print("Enter your password:")
                bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
                if err != nil {
                    fmt.Println("Error reading password:", err)
                    return
                }
                password = string(bytePassword)
                fmt.Println()
            }
            // fmt.Println(host, username, password, group)
            if password != "" {
                params := make(map[string]string)
                params["log_level"] = logLevel
                params["log_path"] = logPath

                result := gson.New()
                err := rpcCall("config", params, result, rpc.CONFIG)
                if err != nil {
                    after, _ := strings.CutPrefix(err.Error(), "jsonrpc2: code 1 message: ")
                    fmt.Println(after)
                } else {
                    params := make(map[string]string)
                    params["host"] = host
                    params["username"] = username
                    params["password"] = password
                    params["group"] = group
                    params["secret"] = secret

                    err := rpcCall("connect", params, result, rpc.CONNECT)
                    if err != nil {
                        after, _ := strings.CutPrefix(err.Error(), "jsonrpc2: code 1 message: ")
                        fmt.Println(after)
                    } else {
                        result.Print()
                    }
                }
            }
        }
    },
}

func init() {
    // 子命令自己被编译、添加到主命令当中
    rootCmd.AddCommand(connect)

    // 将 Flag 解析到全局变量
    connect.Flags().StringVarP(&host, "server", "s", "", "VPN server")
    connect.Flags().StringVarP(&username, "username", "u", "", "User name")
    connect.Flags().StringVarP(&password, "password", "p", "", "User password")
    connect.Flags().StringVarP(&group, "group", "g", "", "User group")
    connect.Flags().StringVarP(&secret, "key", "k", "", "Secret key")

    connect.Flags().StringVarP(&logLevel, "log_level", "l", "info", "Set the log level")
    connect.Flags().StringVarP(&logPath, "log_path", "d", os.TempDir(), "Set the log directory")
}
