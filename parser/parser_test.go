package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	jsonLog     = []byte("{\"remote_addr\":\"66.102.6.200\",\"time_local\":\"15/Nov/2021:13:44:10 +0800\",\"request\":\"GET / HTTP/1.1\",\"status\":200,\"body_bytes_sent\":1603,\"http_user_agent\":\"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36 Google Favicon\",\"request_time\":0.20}\n")
	combinedLog = []byte("103.131.71.189 - - [31/Oct/2023:19:07:45 +0700] \"GET /robots.txt HTTP/1.1\" 200 182 \"-\" \"Mozilla/5.0 (compatible; coccocbot-web/1.0; +http://help.coccoc.com/searchengine)\"\n")
	// combinedLog = []byte(`253.211.236.165 [10/Sep/2015:17:58:28 +0000] "GET /t/40x40/e3/2a/090e68d68d67eff9cc6de34b5e5b.jpeg HTTP/1.1" 404 785 98 0.021`)
	apacheLog = []byte(`40.77.167.52 - - [31/Oct/2023:19:07:56 +0700] "GET /checkout/cart/add?product_id=896&redirect=true HTTP/2" 302 0 "-" "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/103.0.5060.134 Safari/537.36"`)
	iisLog    = []byte(`211.251.138.161 [10/Sep/2015:17:58:28 +0000] "GET /t/40x40/dc/0b/bdbef36aee8a0bef2983c88c49d3.jpeg HTTP/1.1" 200 786 1037 0.798 "40x40" 791 4`)
	NCSALog   = []byte(`10.100.10.45 - BMAA\will.smith [01/Jul/2013:07:17:28 +0200] "GET /Download/__Omnia__Aus- und Weiterbildung__Konsular- und Verwaltungskonferenz, Programm.doc HTTP/1.1" 200 9076810`)
)

func TestParseTime(t *testing.T) {
	datetime := ParseTime("01/Nov/2021:00:00:00 +0800")
	assert.NotNil(t, datetime)
	assert.Equal(t, int64(1635696000000), datetime.UnixMilli())
}

func TestParseLogJson(t *testing.T) {
	logInfo := NewJsonParser().ParseLog(jsonLog)
	assert.NotNil(t, logInfo)
	assert.Equal(t, "66.102.6.200", logInfo.RemoteAddr)
	assert.Equal(t, "", logInfo.RemoteUser)
	assert.Equal(t, "15/Nov/2021:13:44:10 +0800", logInfo.TimeLocal)
	assert.Equal(t, "GET / HTTP/1.1", logInfo.Request)
	assert.Equal(t, 200, logInfo.Status)
	assert.Equal(t, 1603, logInfo.BodyBytesSent)
	assert.Equal(t, "", logInfo.HttpReferer)
	assert.Equal(t, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36 Google Favicon", logInfo.HttpUserAgent)
	assert.Equal(t, 0.20, logInfo.RequestTime)
}

func TestParseLogCombined(t *testing.T) {
	logInfo := NewCombinedParser().ParseLog(combinedLog)
	assert.NotNil(t, logInfo)
	assert.Equal(t, "103.131.71.189", logInfo.RemoteAddr)
	assert.Equal(t, "-", logInfo.RemoteUser)
	assert.Equal(t, "31/Oct/2023:19:07:45 +0700", logInfo.TimeLocal)
	assert.Equal(t, "GET /robots.txt HTTP/1.1", logInfo.Request)
	assert.Equal(t, 200, logInfo.Status)
	assert.Equal(t, 182, logInfo.BodyBytesSent)
	assert.Equal(t, "-", logInfo.HttpReferer)
	assert.Equal(t, "Mozilla/5.0 (compatible; coccocbot-web/1.0; +http://help.coccoc.com/searchengine)", logInfo.HttpUserAgent)
}

func TestCustomLog(t *testing.T) {
	aLog := NewCustomParser().ParseLog(apacheLog)
	iLog := NewCustomParser().ParseLog(iisLog)
	nLog := NewCustomParser().ParseLog(NCSALog)

	// apache log
	assert.NotNil(t, aLog)
	assert.Equal(t, "40.77.167.52", aLog.RemoteAddr)
	assert.Equal(t, "", aLog.RemoteUser)
	assert.Equal(t, "31/Oct/2023:19:07:56 +0700", aLog.TimeLocal)
	assert.Equal(t, "GET", aLog.Method)
	assert.Equal(t, "/checkout/cart/add?product_id=896&redirect=true", aLog.Request)
	assert.Equal(t, "HTTP/2", aLog.Protocol)
	assert.Equal(t, 302, aLog.Status)
	assert.Equal(t, 0, aLog.BodyBytesSent)
	assert.Equal(t, "", aLog.HttpReferer)
	assert.Equal(t, "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/103.0.5060.134 Safari/537.36", aLog.HttpUserAgent)

	assert.NotNil(t, iLog)
	assert.Equal(t, "211.251.138.161", iLog.RemoteAddr)
	assert.Equal(t, "", iLog.RemoteUser)
	assert.Equal(t, "10/Sep/2015:17:58:28 +0000", iLog.TimeLocal)
	assert.Equal(t, "GET", iLog.Method)
	assert.Equal(t, "/t/40x40/dc/0b/bdbef36aee8a0bef2983c88c49d3.jpeg", iLog.Request)
	assert.Equal(t, "HTTP/1.1", iLog.Protocol)
	assert.Equal(t, 200, iLog.Status)
	assert.Equal(t, 786, iLog.BodyBytesSent)
	assert.Equal(t, 0.798, iLog.RequestTime)

	assert.NotNil(t, nLog)
	assert.Equal(t, "10.100.10.45", nLog.RemoteAddr)
	assert.Equal(t, `BMAA\will.smith`, nLog.RemoteUser)
	assert.Equal(t, "01/Jul/2013:07:17:28 +0200", nLog.TimeLocal)
	assert.Equal(t, "GET", nLog.Method)
	assert.Equal(t, "/Download/__Omnia__Aus- und Weiterbildung__Konsular- und Verwaltungskonferenz, Programm.doc", nLog.Request)
	assert.Equal(t, "HTTP/1.1", nLog.Protocol)
	assert.Equal(t, 200, nLog.Status)
	assert.Equal(t, 9076810, nLog.BodyBytesSent)
}
