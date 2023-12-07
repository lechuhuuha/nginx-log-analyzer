package parser

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"time"

	"github.com/fantasticmao/nginx-log-analyzer/ioutil"
)

const (
	LogFormatTypeCombined = "combined"
	LogFormatTypeJson     = "json"
	ApacheFormat          = `^([^ ]+) [^ ]+ ([^\/\[]+) \[([^ ]+ [^ ]+)\] \"([A-Z]+) (\S+) (HTTP\/[0-9.]+)" ([\d|-]+) ([\d|-]+) \"(.*?)\" \"([^\"]*)\"`
	IISFormat             = `^(\S+) \[([^ ]+ [^ ]+)\] "([A-Z]+) (\S+) (HTTP\/[0-9.]+)" ([\d|-]+) ([\d|-]+) \S+ (\S+) (\S+)`
	NCSAFormat            = `^([^ ]+) [^ ]+ (.+) \[([^ ]+ [^ ]+)\] \"([^ ]+) (.+) (HTTP\/[0-9.]+)\" ([\d|-]+) ([\d|-]+)`
	ApacheFormatName      = "ApacheFormat"
	IISFormatName         = "IISFormat"
	NCSAFormatName        = "NCSAFormat"
)

type (
	Parser interface {
		ParseLog(line []byte) *LogInfo
	}
	JsonParser struct {
	}
	CombinedParser struct {
		delimiters [][]byte
	}
	CombinedParser2 struct {
		delimiters [][]byte
	}
	CustomParser struct {
	}
)

func ParseTime(timeLocal string) time.Time {
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", timeLocal)
	if err != nil {
		ioutil.Fatal("parse log time error: %v\n", err.Error())
	}
	return t
}

func NewJsonParser() *JsonParser {
	return &JsonParser{}
}

func (parser *JsonParser) ParseLog(line []byte) *LogInfo {
	logInfo := &LogInfo{}
	err := json.Unmarshal(line[:len(line)-1], logInfo)
	if err != nil {
		ioutil.Fatal("parse json log error: %v\n", err.Error())
		return nil
	}
	return logInfo
}

func NewCombinedParser() *CombinedParser {
	// log_format combined '103.131.71.189 - - [31/Oct/2023:19:07:45 +0700] "GET /robots.txt HTTP/1.1" 200 182 "-" "Mozilla/5.0 (compatible; coccocbot-web/1.0; +http://help.coccoc.com/searchengine)"';
	var delimiters = [][]byte{
		[]byte(" - "), []byte(" ["), []byte("] \""), []byte("\" "), []byte(" "), []byte(" \""), []byte("\" \""), []byte("\"\n"),
	}
	return &CombinedParser{
		delimiters: delimiters,
	}
}

func (parser *CombinedParser) ParseLog(line []byte) *LogInfo {
	var (
		variables = make([]string, 0, 8)
		i         = 0 // variable start index
		j         = 0 // variable end index
		k         = 0 // delimiters and variables index
	)
	for k < len(parser.delimiters) && j <= len(line)-len(parser.delimiters[k]) {
		if bytes.Equal(line[j:j+len(parser.delimiters[k])], parser.delimiters[k]) {
			variables = append(variables, string(line[i:j]))
			j = j + len(parser.delimiters[k])
			i = j
			k++
		} else {
			j++
		}
	}
	if k != len(parser.delimiters) {
		ioutil.Fatal("parse combined log error: %v\n", string(line))
	}
	status, err := strconv.Atoi(variables[4])
	if err != nil {
		ioutil.Fatal("convert $status to int error: %v\n", variables[4])
	}
	bodyBytesSent, err := strconv.Atoi(variables[5])
	if err != nil {
		ioutil.Fatal("convert $body_bytes_sent to int error: %v\n", variables[5])
	}
	return &LogInfo{
		RemoteAddr:    variables[0],
		RemoteUser:    variables[1],
		TimeLocal:     variables[2],
		Request:       variables[3],
		Status:        status,
		BodyBytesSent: bodyBytesSent,
		HttpReferer:   variables[6],
		HttpUserAgent: variables[7],
	}
}

func NewCustomParser() *CustomParser {
	return &CustomParser{}
}

func (parser *CustomParser) ParseLog(line []byte) *LogInfo {
	// autodetect what type of regex to use
	// 1. ApacheFormat (?^:^([^ ]+) [^ ]+ ([^\/\[]+) \[([^ ]+) [^ ]+\] \"([^ ]+) ([^ ]+)(?: [^\"]+|)\" ([\d|-]+) ([\d|-]+) \"(.*?)\" \"([^\"]*)\")
	// 2. IISFormat (?^:^(\S+ \S+) (\S+) (\S+) (\S+) (\S+) ([\d|-]+) ([\d|-]+) \S+ (\S+) (\S+))
	// 3. WebstartFormat (?^:^([^\t]*\t[^\t]*)\t([^\t]*)\t([\d|-]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t[^\t]*\t([^\t]*)\t([\d]*))
	// 4. NCSAFormat (?^:^([^ ]+) [^ ]+ (.+) \[([^ ]+) [^ ]+\] \"([^ ]+) (.+) [^\"]+\" ([\d|-]+) ([\d|-]+))
	matches, formatType := parser.MatchRegex(string(line))
	switch formatType {
	case ApacheFormatName:
		if len(matches) < 10 {
			break
		}
		status, err := strconv.Atoi(matches[7])
		if err != nil {
			status = 500
		}
		bodyBytesSent, err := strconv.Atoi(matches[8])
		if err != nil {
			bodyBytesSent = 0
		}
		return &LogInfo{
			RemoteAddr:    matches[1],
			TimeLocal:     matches[3],
			Method:        matches[4],
			Request:       matches[5],
			Protocol:      matches[6],
			Status:        status,
			BodyBytesSent: bodyBytesSent,
			HttpUserAgent: matches[10],
		}
	case IISFormatName:
		if len(matches) < 10 {
			break
		}
		status, err := strconv.Atoi(matches[6])
		if err != nil {
			status = 500
		}
		bodyBytesSent, err := strconv.Atoi(matches[7])
		if err != nil {
			bodyBytesSent = 0
		}
		floatValue, err := strconv.ParseFloat(matches[8], 64)
		if err != nil {
			floatValue = 0
		}
		return &LogInfo{
			RemoteAddr:    matches[1],
			TimeLocal:     matches[2],
			Method:        matches[3],
			Request:       matches[4],
			Protocol:      matches[5],
			Status:        status,
			BodyBytesSent: bodyBytesSent,
			HttpUserAgent: matches[9],
			RequestTime:   floatValue,
		}
	case NCSAFormatName:
		if len(matches) < 9 {
			break
		}
		status, err := strconv.Atoi(matches[7])
		if err != nil {
			status = 500
		}
		bodyBytesSent, err := strconv.Atoi(matches[8])
		if err != nil {
			bodyBytesSent = 0
		}
		return &LogInfo{
			RemoteAddr:    matches[1],
			RemoteUser:    matches[2],
			TimeLocal:     matches[3],
			Method:        matches[4],
			Request:       matches[5],
			Protocol:      matches[6],
			Status:        status,
			BodyBytesSent: bodyBytesSent,
		}
	}
	return nil
}

func (parser *CustomParser) MatchRegex(input string) ([]string, string) {

	if match, _ := regexp.MatchString(ApacheFormat, input); match {
		return regexp.MustCompile(ApacheFormat).FindStringSubmatch(input), ApacheFormatName
	}
	if match, _ := regexp.MatchString(IISFormat, input); match {
		return regexp.MustCompile(IISFormat).FindStringSubmatch(input), IISFormatName
	}
	if match, _ := regexp.MatchString(NCSAFormat, input); match {
		return regexp.MustCompile(NCSAFormat).FindStringSubmatch(input), NCSAFormatName
	}

	return nil, ""
}
