package base

func Setup() {
    initCfg()
    // 默认启动日志作用于 rpc 服务启动和 UI 连接到 rpc 服务，UI 需要在连接成功或修改配置后主动推送配置
    InitLog()
}
