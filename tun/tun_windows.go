package tun

import (
    "context"
    "errors"
    "fmt"
    "github.com/lysShub/wintun-go"
    "golang.org/x/sys/windows"
    "golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
    "os"
    "sync"
    "sync/atomic"
)

type NativeTun struct {
    wt   *wintun.Adapter
    name string
    mtu  int

    closeOnce sync.Once
    close     atomic.Bool
}

var (
    WintunTunnelType          = "TLSLink Secure"
    WintunStaticRequestedGUID = &windows.GUID{
        0x0000000,
        0xFFFF,
        0xFFFF,
        [8]byte{0xFF, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e},
    }
)

func init() {
    wintun.MustLoad(wintun.DLL)
}

func CreateTUN(ifname string, mtu int) (Device, error) {
    wt, err := wintun.CreateAdapter(ifname,
        wintun.TunType(WintunTunnelType),
        wintun.Guid(WintunStaticRequestedGUID),
        wintun.RingBuff(0x800000)) // 8 MiB, 5个 0 为 1 MiB

    tun := &NativeTun{
        wt:   wt,
        name: ifname,
        mtu:  mtu,
    }

    return tun, err
}

func (tun *NativeTun) File() *os.File {
    return nil
}

func (tun *NativeTun) Read(buff []byte, offset int) (int, error) {

    if tun.close.Load() {
        return 0, os.ErrClosed
    }

    for {
        packet, err := tun.wt.Recv(context.Background())
        switch err {
        case nil:
            packetSize := len(packet)
            copy(buff[offset:], packet)
            tun.wt.Release(packet)
            // tun.rate.update(uint64(packetSize))
            return packetSize, nil
        case windows.ERROR_HANDLE_EOF:
            return 0, os.ErrClosed
        case windows.ERROR_INVALID_DATA:
            return 0, errors.New("send ring corrupt")
        }
        return 0, fmt.Errorf("read failed: %w", err)
    }
}

func (tun *NativeTun) Write(buff []byte, offset int) (int, error) {

    if tun.close.Load() {
        return 0, os.ErrClosed
    }

    packetSize := len(buff) - offset

    packet, err := tun.wt.Alloc(packetSize)
    if err == nil {
        copy(packet, buff[offset:])
        err = tun.wt.Send(packet)
        if err != nil {
            return 0, err
        }
        return int(packetSize), nil
    }
    switch err {
    case windows.ERROR_HANDLE_EOF:
        return 0, os.ErrClosed
    case windows.ERROR_BUFFER_OVERFLOW:
        return 0, nil // Dropping when ring is full.
    }
    return 0, fmt.Errorf("write failed: %w", err)
}

func (tun *NativeTun) Flush() error {
    return nil
}

func (tun *NativeTun) MTU() (int, error) {
    return tun.mtu, nil
}

func (tun *NativeTun) Name() (string, error) {
    return tun.name, nil
}

func (tun *NativeTun) Events() <-chan Event {
    return nil
}

func (tun *NativeTun) Close() error {
    tun.closeOnce.Do(func() {
        tun.close.Store(true)

        if tun.wt != nil {
            tun.wt.Close()
        }
    })

    return nil
}

func (tun *NativeTun) LUID() winipcfg.LUID {
    luid, err := tun.wt.GetAdapterLuid()
    if err != nil {
        return 0
    }
    return luid
}
