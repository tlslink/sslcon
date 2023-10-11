package cmd

import (
    "fmt"
    "github.com/spf13/cobra"
    "os"
)

var rootCmd = &cobra.Command{
    Use: "cli",
    Long: `A CLI application that supports the OpenConnect SSL VPN protocol.
For more information, please visit https://github.com/tlslink/vpnagent`,
    CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true},
    // rootCmd.Execute() 执行完成之前调用
    Run: func(cmd *cobra.Command, args []string) { // 若执行子命令或者帮助或者出现错误，则不会执行这里
        cmd.Help()
    },
}

func Execute() {
    rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
