package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
	"time"

	"github.com/fantasticmao/nginx-log-analyzer/handler"
	"github.com/fantasticmao/nginx-log-analyzer/ioutil"
	"github.com/fantasticmao/nginx-log-analyzer/parser"
)

var (
	logFiles     []string
	showVersion  bool
	configDir    string
	analysisType int
	limit        int
	limitSecond  int
	percentile   float64
	timeAfter    string
	timeBefore   string
	logFormat    string
	multiThread  bool
	err          error
)

var (
	Name       = "nginx-log-analyzer"
	Version    string
	BuildTime  string
	CommitHash string
)

type (
	loganalyzer struct {
		parser  parser.Parser
		handler handler.Handler
		since   time.Time
		util    time.Time
		wg      sync.WaitGroup
	}
)

func (l *loganalyzer) add() {
	l.wg.Add(1)
}

func NewLogAnalyzer() loganalyzer {
	return loganalyzer{}
}

func init() {
	flag.BoolVar(&showVersion, "v", false, "show current version")
	flag.BoolVar(&multiThread, "m", true, "use concurrent model")
	flag.StringVar(&configDir, "d", "", "specify the configuration directory")
	flag.IntVar(&analysisType, "t", 0, "specify the analysis type, see documentation for more details:\nhttps://github.com/fantasticmao/nginx-log-analyzer#specify-the-analysis-type--t")
	flag.IntVar(&limit, "n", 15, "limit the output lines number")
	flag.IntVar(&limitSecond, "n2", 15, "limit the secondary output lines number in '-t 4' mode")
	flag.Float64Var(&percentile, "p", 95, "specify the percentile value in '-t 7' mode")
	flag.StringVar(&timeAfter, "ta", "", "limit the analysis start time, in format of RFC3339 e.g. '2021-11-01T00:00:00+08:00'")
	flag.StringVar(&timeBefore, "tb", "", "limit the analysis end time, in format of RFC3339 e.g. '2021-11-02T00:00:00+08:00'")
	flag.StringVar(&logFormat, "lf", "combined", "specify the nginx log format, value should be 'combined' or 'json'")
	flag.Parse()
	logFiles = flag.Args()
}

func main() {
	if showVersion {
		fmt.Printf("%v %v build at %v on commit %v\n", Name, Version, BuildTime, CommitHash)
		return
	}

	if configDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			ioutil.Fatal("get user home directory error: %v\n", err.Error())
			return
		}
		configDir = path.Join(homeDir, ".config", Name)
	}
	loganalyze := NewLogAnalyzer()
	if timeAfter != "" {
		loganalyze.since, err = time.Parse(time.RFC3339, timeAfter)
		if err != nil {
			ioutil.Fatal("parse start time error: %v\n", err.Error())
			return
		}
	}
	if timeBefore != "" {
		loganalyze.util, err = time.Parse(time.RFC3339, timeBefore)
		if err != nil {
			ioutil.Fatal("parse end time error: %v\n", err.Error())
			return
		}
	}

	loganalyze.parser = newLogParser()
	loganalyze.handler = newLogHandler()
	testProcess(logFiles, &loganalyze)

}

func newLogHandler() handler.Handler {
	switch analysisType {
	case handler.AnalysisTypePvAndUv:
		return handler.NewPvAndUvHandler()
	case handler.AnalysisTypeVisitedIps:
		return handler.NewMostVisitedFieldsHandler(analysisType)
	case handler.AnalysisTypeVisitedUris:
		return handler.NewMostVisitedFieldsHandler(analysisType)
	case handler.AnalysisTypeVisitedUserAgents:
		return handler.NewMostVisitedFieldsHandler(analysisType)
	case handler.AnalysisTypeVisitedLocations:
		const dbFile = "City.mmdb"
		return handler.NewMostVisitedLocationsHandler(path.Join(configDir, dbFile), limitSecond)
	case handler.AnalysisTypeResponseStatus:
		return handler.NewMostFrequentStatusHandler()
	case handler.AnalysisTypeAverageTimeUris:
		return handler.NewLargestAverageTimeUrisHandler()
	case handler.AnalysisTypePercentTimeUris:
		return handler.NewLargestPercentTimeUrisHandler(percentile)
	default:
		ioutil.Fatal("unsupported analysis type: %v\n", analysisType)
		return nil
	}
}

func newLogParser() parser.Parser {
	switch logFormat {
	case parser.LogFormatTypeCombined:
		return parser.NewCombinedParser()
	case parser.LogFormatTypeJson:
		return parser.NewJsonParser()
	default:
		ioutil.Fatal("unsupported log format : %v\n", logFormat)
		return nil
	}
}

func isDateSkipAble(loganalyzer *loganalyzer, logInfo *parser.LogInfo) bool {
	if !loganalyzer.since.IsZero() || !loganalyzer.util.IsZero() {
		logTime := parser.ParseTime(logInfo.TimeLocal)
		if !loganalyzer.since.IsZero() && logTime.Before(loganalyzer.since) {
			// go to next line
			return true
		}
		if !loganalyzer.util.IsZero() && logTime.After(loganalyzer.util) {
			// go to next file
			return true
		}
	}
	return false
}

func parseLog(loganalyzer *loganalyzer, data []byte) {
	logInfo := loganalyzer.parser.ParseLog(data)
	skipAble := isDateSkipAble(loganalyzer, logInfo)
	if skipAble {
		return
	}
	loganalyzer.handler.Input(logInfo)
}

func generator(tokens chan<- []byte, logFile string) {
	file, isGzip := ioutil.OpenFile(logFile)
	reader, err := ioutil.ReadFile(file, isGzip)
	if err != nil {
		ioutil.Fatal(err.Error())
	}
	defer func() {
		err := file.Close()
		if err != nil {
			ioutil.Fatal("close file error: %v\n", err.Error())
		}
		close(tokens)
	}()

	for {
		data, err := reader.ReadBytes('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			break
		}
		tokens <- data // acquire a token
	}

}

func merge(loganalyzer *loganalyzer, data <-chan []byte, wg *sync.WaitGroup) {
	for d := range data {
		wg.Add(1)
		go func(pLog []byte) {
			defer wg.Done()
			parseLog(loganalyzer, pLog)
		}(d)
	}
}

func process(logFiles []string, loganalyzer *loganalyzer) {
	start := time.Now()
	var (
		wg sync.WaitGroup
		// tokens = make(chan []byte, 100000)
	)
	for _, logFile := range logFiles {
		tokens := make(chan []byte, 100000)
		wg.Add(2)
		go func() {
			defer wg.Done()
			generator(tokens, logFile)
		}()
		go func() {
			defer func() {
				wg.Done()
			}()
			merge(loganalyzer, tokens, &wg)
		}()
	}
	// 5. print result
	wg.Wait()
	// loganalyzer.handler.Output(limit)
	fmt.Printf("%s took %v\n", "job", time.Since(start))
}

func testProcess(logFiles []string, loganalyzer *loganalyzer) {
	start := time.Now()
	var wg sync.WaitGroup
	for _, logFile := range logFiles {
		// 1. open and read file
		file, isGzip := ioutil.OpenFile(logFile)
		reader, err := ioutil.ReadFile(file, isGzip)
		if err != nil {
			ioutil.Fatal("read file error: %v\n", err.Error())
		}
		for {

			data, err := reader.ReadBytes('\n')
			if err == io.EOF {
				break
			} else if err != nil {
				ioutil.Fatal("read file error: %v\n", err.Error())
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				// 2. parse line
				logInfo := loganalyzer.parser.ParseLog(data)

				// 3. datetime filter
				if !loganalyzer.since.IsZero() || !loganalyzer.util.IsZero() {
					logTime := parser.ParseTime(logInfo.TimeLocal)
					if !loganalyzer.since.IsZero() && logTime.Before(loganalyzer.since) {
						// go to next line
						return
					}
					if !loganalyzer.util.IsZero() && logTime.After(loganalyzer.util) {
						// go to next file
						return
					}
				}
				// 4. process data
				loganalyzer.handler.Input(logInfo)
			}()
		}
		wg.Wait()
		// 5. close file handler
		err = file.Close()
		if err != nil {
			ioutil.Fatal("close file error: %v\n", err.Error())
			return
		}
	}
	// 5. print result
	// loganalyzer.handler.Output(limit)
	fmt.Printf("%s took %v\n", "job", time.Since(start))
}
