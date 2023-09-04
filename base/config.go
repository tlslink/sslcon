package base

var (
    Cfg            = &ClientConfig{}
    LocalInterface = &Interface{}
)

type ClientConfig struct {
    LogLevel           string `json:"log_level"`
    LogPath            string `json:"log_path"`
    InsecureSkipVerify bool   `json:"skip_verify"`
    CiscoCompat        bool   `json:"cisco_compat"`
    AgentName          string `json:"agent_name"`
    AgentVersion       string `json:"agent_version"`
    CiscoAgentVersion  string
}

// Interface 应该由外部接口设置
type Interface struct {
    Name    string `json:"name"`
    Ip4     string `json:"ip4"`
    Mac     string `json:"mac"`
    Gateway string `json:"gateway"`
}

func initCfg() {
    Cfg.LogLevel = "Debug"
    Cfg.InsecureSkipVerify = true
    Cfg.CiscoCompat = true
    Cfg.AgentName = "AnyLink Secure Client"
    Cfg.AgentVersion = "0.2.0.6"
    Cfg.CiscoAgentVersion = "4.10.07062"
}
