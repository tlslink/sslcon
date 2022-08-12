package vpn

import (
    "sync"
    "vpnagent/proto"
)

const BufferSize = 2048

// pool 实际数据缓冲区，缓冲区的容量由 golang 自动控制，PayloadIn 等通道只是个内存地址列表
var pool = sync.Pool{
    New: func() interface{} {
        b := make([]byte, BufferSize)
        pl := proto.Payload{
            PType: 0x00,
            Data:  b,
        }
        return &pl
    },
}

func getPayloadBuffer() *proto.Payload {
    pl := pool.Get().(*proto.Payload)
    return pl
}

func putPayloadBuffer(pl *proto.Payload) {
    // DPD-REQ、KEEPALIVE 等数据
    if cap(pl.Data) != BufferSize {
        // base.Debug("payload is:", pl.Data)
        return
    }

    pl.PType = 0x00
    pl.Data = pl.Data[:BufferSize]
    pool.Put(pl)
}
