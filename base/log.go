package base

/*
extern void osLog(const char *message);
*/
import "C"
import (
	"fmt"
	"log"
	"os"
	"path"
	"runtime"
	"strings"
)

// 相当于枚举，只有小于设置级别的日志才会输出，不区分大小写
// Debug < Info < Warn < Error < Fatal
const (
	_Debug = iota
	_Info
	_Warn
	_Error
	_Fatal
)

var (
	baseWriter *logWriter
	baseLogger *log.Logger
	baseLevel  int
	levels     map[int]string

	logName = "vpnagent.log"
)

type logWriter struct {
	UseStdout bool
	UseOSLog  bool
	FileName  string
	File      *os.File
	NowDate   string
}

// 由 initLog() 中的 log.New 注册调用
func (lw *logWriter) Write(p []byte) (n int, err error) {
	return lw.File.Write(p)
}

// 创建新文件
func (lw *logWriter) newFile() error {
	if lw.UseStdout {
		lw.File = os.Stdout
		return nil
	}
	if Cfg.LogPath != "" {
		err := os.MkdirAll(Cfg.LogPath, os.ModePerm)
		if err != nil {
			baseWriter.UseStdout = true
			lw.File = os.Stdout
			return err
		}
	}
	// 客户端不需要内容追加，每次重启客户端或者配置更改重新生成干净日志，即使 root 权限，os.OpenFile 也不能打开其它用户文件，但能删除！
	_ = os.Remove(lw.FileName)
	f, err := os.OpenFile(lw.FileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		baseWriter.UseStdout = true
		lw.File = os.Stdout
		return err
	}
	lw.File = f
	return nil
}

func InitLog() {
	// 初始化 baseLogger
	baseWriter = &logWriter{
		UseStdout: Cfg.LogPath == "",
		FileName:  path.Join(Cfg.LogPath, logName),
	}
	baseLevel = logLevel2Int(Cfg.LogLevel)
	baseLogger = log.New(baseWriter, "", log.LstdFlags|log.Lshortfile)

	err := baseWriter.newFile()
	// newFile will reset baseWriter.UseStdout
	baseWriter.UseOSLog = baseWriter.UseStdout && (runtime.GOOS == "darwin" || runtime.GOOS == "ios" || runtime.GOOS == "android")
	if err != nil {
		Error(err)
	}
}

func GetBaseLogger() *log.Logger {
	return baseLogger
}

func logLevel2Int(l string) int {
	levels = map[int]string{
		_Debug: "Debug",
		_Info:  "Info",
		_Warn:  "Warn",
		_Error: "Error",
		_Fatal: "Fatal",
	}
	lvl := _Info
	for k, v := range levels {
		if strings.EqualFold(strings.ToLower(l), strings.ToLower(v)) {
			lvl = k
		}
	}
	return lvl
}

func output(l int, s ...interface{}) {
	lvl := fmt.Sprintf("[%s] ", levels[l])
	// 只有真正需要输出的时候才判断，正常应用应该运行在 info 模式
	if baseWriter.UseOSLog {
		C.osLog(C.CString(lvl + fmt.Sprintln(s...)))
	} else {
		_ = baseLogger.Output(3, lvl+fmt.Sprintln(s...))
	}
}

func Debug(v ...interface{}) {
	l := _Debug
	if baseLevel > l {
		return
	}
	output(l, v...)
}

func Info(v ...interface{}) {
	l := _Info
	if baseLevel > l {
		return
	}
	output(l, v...)
}

func Warn(v ...interface{}) {
	l := _Warn
	if baseLevel > l {
		return
	}
	output(l, v...)
}

func Error(v ...interface{}) {
	l := _Error
	if baseLevel > l {
		return
	}
	output(l, v...)
}

func Fatal(v ...interface{}) {
	l := _Fatal
	if baseLevel > l {
		return
	}
	output(l, v...)
	os.Exit(1)
}
