package server

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/ethereum/go-ethereum/thunder/lumberjack"
	"github.com/ethereum/go-ethereum/thunder/lumberjack/syscall_wrap"
	"github.com/ethereum/go-ethereum/thunder/pala/server/internal/configreader"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/commitsha1"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	ethLog "github.com/ethereum/go-ethereum/log"
	"golang.org/x/xerrors"
)

const (
	RotatingLogOutputMode  = "rotating"
	StdoutLogOutputMode    = "stdout"
	StderrLogOutputMode    = "stderr"
	ethLogLvl              = ethLog.LvlWarn
	logLevelPrefix         = "loglevel."
	verboseLogFileLevelKey = "verboseLogFileLevel"
)

var memWriter = new(bytes.Buffer)

func SetupEthLogging(ethLogFile, ethLogFilter string) error {
	ethLogWriter := &lumberjack.Logger{
		Filename:      ethLogFile,
		MaxSize:       50, // in megabytes, size at which it rotates logfiles
		MaxBackups:    10, // 0 == keep all backup log files
		DoCompression: true,
	}
	// geth logging
	gLogger := ethLog.NewGlogHandler(ethLog.StreamHandler(ethLogWriter, ethLog.TerminalFormat(false)))
	// example "trie=4,state=4"
	if err := gLogger.Vmodule(ethLogFilter); err != nil {
		log.Fatalf("Failed to set log filter: %s", err.Error())
		return err
	}
	ethLog.Root().SetHandler(gLogger)
	return nil
}

// SetupLogging configures the different loggers used by
// different parts of the code and Go's panic to log to a common file.
// `outputMode`: one of { `RotatingLogOutputMode`, `StdoutLogOutputMode`}
// `filename`: path to log file if `outputMode` is not `stdoutLogOutputMode`
func SetupLogging(outputMode, filename, verboseFileName string) error {
	var err error
	commitSha1 := fmt.Sprintf("CommitSha1: %s", commitsha1.CommitSha1)
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)

	var logWriter io.Writer
	switch outputMode {
	case RotatingLogOutputMode:
		logWriter = &lumberjack.Logger{
			Filename:       filename,
			MaxSize:        50, // in megabytes, size at which it rotates logfiles
			MaxBackups:     10, // 0 == keep all backup log files
			DoCompression:  true,
			LogfilePrefix:  commitSha1,
			RedirectStderr: true,
		}
		verboseWriter := &lumberjack.Logger{
			Filename:      verboseFileName,
			MaxSize:       50, // in megabytes, size at which it rotates logfiles
			MaxBackups:    10, // 0 == keep all backup log files
			DoCompression: true,
			LogfilePrefix: commitSha1,
		}

		lgr.SetWriter(logWriter)
		lgr.SetVerboseWriter(verboseWriter)
		logWriter = io.MultiWriter(logWriter, verboseWriter)
		log.SetOutput(logWriter)
	case StdoutLogOutputMode:
		logWriter = os.Stdout
		// Golang sends panics to stderr.  We want to capture panics in the log.  We'll do
		// this by redirecting stderr to stdout.  The code does this separately for each
		// logger output type because in the rotating logger output mode this is done inside
		// of the lumberjack library, because it needs to do it each time it rotates the
		// log file.  In the stdout case we only need to do this once, so we do it here
		err := syscall_wrap.Dup2(syscall.Stdout, syscall.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stdout, "Failed to redirect stderr to stdout: %v", err)
		}
		lgr.SetWriter(logWriter)
		log.SetOutput(logWriter)
	case StderrLogOutputMode:
		logWriter = os.Stderr
		lgr.SetWriter(logWriter)
		log.SetOutput(logWriter)
	default:
		logOutputModePrompt := fmt.Sprintf(
			"Legal values are '%s %s' (default), '%s'",
			RotatingLogOutputMode,
			StderrLogOutputMode,
			StdoutLogOutputMode,
		)
		debug.Fatal("unknown log output mode %q. %s", outputMode, logOutputModePrompt)
	}

	ethLog.SetThunderLgr(lgr.NewLgr("/eth"))
	log.Print(commitSha1) // use to identify the program binary version from logs
	log.Printf("Called as %+q", os.Args)

	// copy the data that was logged before the logger was configured to the output writer
	if memWriter != nil {
		_, err = logWriter.Write(memWriter.Bytes())
		memWriter.Reset()
		memWriter = nil
	}
	return err
}

// captureEarlyLogging is designed to be called from `init()` thus enabling
// the collection of "early" logging performed before `SetupLogging()` is called
func captureEarlyLogging() {
	w := memWriter
	lgr.SetWriter(w)
	log.SetOutput(w)
	h := ethLog.NewGlogHandler(ethLog.StreamHandler(
		w, ethLog.TerminalFormat(false)))
	h.Verbosity(ethLogLvl)
	ethLog.Root().SetHandler(h)
}

func init() {
	if utils.InTest() {
		// Log to the console when running the tests.
		return
	}
	captureEarlyLogging()
}

type logLevelFromConfig struct {
	logLevelPrefix string
}

func newLogLevelFromConfig(logLevelPrefix string) *logLevelFromConfig {
	return &logLevelFromConfig{strings.ToLower(logLevelPrefix)}
}

func (l *logLevelFromConfig) isLogLevelKey(key string) bool {
	return strings.HasPrefix(key, l.logLevelPrefix)
}

func (l *logLevelFromConfig) configKeyToLgrDomain(key string) string {
	return strings.TrimPrefix(key, l.logLevelPrefix)
}

func (l *logLevelFromConfig) setLogLevelFromConfig(a configreader.AllKeysGetStringer) error {
	// "logLevel.<domain>: INFO" -> lgr.SetLogLevel(<domain>, lgr.LvlInfo)
	for _, key := range a.AllKeys() {
		if l.isLogLevelKey(key) {
			val := a.GetString(key)
			level, err := lgr.LevelFromString(val)
			domain := l.configKeyToLgrDomain(key)
			if err != nil {
				return xerrors.Errorf("invalid log level %q for config key %q: %s", val, key, err)
			}
			err = lgr.SetLogLevel(domain, level)
			if err != nil {
				return xerrors.Errorf("failed to set log level to %d for domain %q: %s", level, domain, err)
			}
		}
	}
	// "verboseLogFileLevel": DEBUG" -> lgr.SetVerboseLogFileLevel(lgr.LvlDebug)
	if val := a.GetString(verboseLogFileLevelKey); val != "" {
		level, err := lgr.LevelFromString(val)
		if err != nil {
			return xerrors.Errorf("invalid verbose log level %q: %s", val, err)
		}
		err = lgr.SetVerboseLogFileLevel(level)
		if err != nil {
			return xerrors.Errorf("failed to set verbose log level to %d: %s", level, err)
		}
	}
	return nil
}

// SetLogLevelFromConfig is designed to be called after `SetupLogging`
func SetLogLevelFromConfig(a configreader.AllKeysGetStringer) error {
	l := newLogLevelFromConfig(logLevelPrefix)
	return l.setLogLevelFromConfig(a)
}
