package cmd

import (
	"context"

	"github.com/gorilla/websocket"
	"github.com/sourcegraph/jsonrpc2"
	ws "github.com/sourcegraph/jsonrpc2/websocket"
)

// type handler struct{}
//
// func (_ *handler) Handle(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) {}
//
// var rpcHandler = handler{}

func rpcCall(method string, params interface{}, result interface{}, id uint64) error {
	conn, _, err := websocket.DefaultDialer.Dial("ws://127.0.0.1:6210/rpc", nil)
	if err != nil {
		return err
	}
	jsonStream := ws.NewObjectStream(conn)
	ctx := context.Background()
	rpcConn := jsonrpc2.NewConn(ctx, jsonStream, nil)
	defer rpcConn.Close()

	return rpcConn.Call(ctx, method, params, result, jsonrpc2.PickID(jsonrpc2.ID{Num: id}))
}
