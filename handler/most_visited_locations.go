package handler

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/fantasticmao/nginx-log-analyzer/cache"
	"github.com/fantasticmao/nginx-log-analyzer/ioutil"
	"github.com/fantasticmao/nginx-log-analyzer/parser"
	geoip2 "github.com/oschwald/geoip2-golang"
)

const (
	countryChina = "China"
	countryJapan = "Japan"
	areaHongKong = "Hong Kong"
	areaTaiwan   = "Taiwan"
	cityUnknown  = "unknown"
)
const (
	languageEn   = "en"
	languageJa   = "ja"
	languageZhCn = "zh-CN"
)

type MostVisitedLocationsHandler struct {
	limitSecond     int
	geoLite2Db      *geoip2.Reader
	ipLocationCache cache.Cache
	// country -> count
	countryCountMap map[string]int
	// country -> city -> count
	countryCityCountMap map[string]map[string]int
	// country -> city -> ip -> count
	countryCityIpCountMap map[string]map[string]map[string]int
}

type locationEntry struct {
	country string
	city    string
}

func NewMostVisitedLocationsHandler(dbFile string, limitSecond int) *MostVisitedLocationsHandler {
	db, err := geoip2.Open(dbFile)
	if err != nil {
		ioutil.Fatal("open MaxMind-DB error: %v\n", err.Error())
		return nil
	}
	return &MostVisitedLocationsHandler{
		limitSecond:           limitSecond,
		geoLite2Db:            db,
		ipLocationCache:       cache.NewLruCache(1000),
		countryCountMap:       make(map[string]int),
		countryCityCountMap:   make(map[string]map[string]int),
		countryCityIpCountMap: make(map[string]map[string]map[string]int),
	}
}

func (handler *MostVisitedLocationsHandler) Input(info *parser.LogInfo) {
	country, city := handler.queryIpLocation(info.RemoteAddr)

	// save or update by country
	if _, ok := handler.countryCityIpCountMap[country]; !ok {
		handler.countryCountMap[country] = 1
		handler.countryCityCountMap[country] = make(map[string]int)
		handler.countryCityIpCountMap[country] = make(map[string]map[string]int)
	} else {
		handler.countryCountMap[country]++
	}

	// save or update by city
	if _, ok := handler.countryCityIpCountMap[country][city]; !ok {
		handler.countryCityCountMap[country][city] = 1
		handler.countryCityIpCountMap[country][city] = make(map[string]int)
	} else {
		handler.countryCityCountMap[country][city]++
	}

	// save or update by ip address
	if _, ok := handler.countryCityIpCountMap[country][city][info.RemoteAddr]; !ok {
		handler.countryCityIpCountMap[country][city][info.RemoteAddr] = 1
	} else {
		handler.countryCityIpCountMap[country][city][info.RemoteAddr]++
	}
}

func (handler *MostVisitedLocationsHandler) Output(limit int) {
	defer handler.geoLite2Db.Close()

	countryCountKeys := make([]string, 0, len(handler.countryCityIpCountMap))
	for k := range handler.countryCityIpCountMap {
		countryCountKeys = append(countryCountKeys, k)
	}
	sort.Slice(countryCountKeys, func(i, j int) bool {
		return handler.countryCountMap[countryCountKeys[i]] > handler.countryCountMap[countryCountKeys[j]]
	})

	for i := 0; i < len(countryCountKeys); i++ {
		country := countryCountKeys[i]
		cityIpCountMap := handler.countryCityIpCountMap[country]
		fmt.Printf("[%v] hits: %v\n", country, handler.countryCountMap[country])

		cityCountKeys := make([]string, 0, len(cityIpCountMap))
		for k := range cityIpCountMap {
			cityCountKeys = append(cityCountKeys, k)
		}
		sort.Slice(cityCountKeys, func(i, j int) bool {
			return handler.countryCityCountMap[country][cityCountKeys[i]] > handler.countryCityCountMap[country][cityCountKeys[j]]
		})

		for j := 0; j < handler.limitSecond && j < len(cityCountKeys); j++ {
			city := cityCountKeys[j]
			ipCountMap := cityIpCountMap[city]
			fmt.Printf("  |--[%v] hits: %v\n", city, handler.countryCityCountMap[country][city])

			ipCountKeys := make([]string, 0, len(ipCountMap))
			for k := range ipCountMap {
				ipCountKeys = append(ipCountKeys, k)
			}
			sort.Slice(ipCountKeys, func(i, j int) bool {
				return ipCountMap[ipCountKeys[i]] > ipCountMap[ipCountKeys[j]]
			})

			for k := 0; k < limit && k < len(ipCountKeys); k++ {
				ip := ipCountKeys[k]
				fmt.Printf("  |  |--\"%v\" hits: %v\n", ip, ipCountMap[ip])
			}
		}
	}
}

func (handler *MostVisitedLocationsHandler) queryIpLocation(ip string) (string, string) {
	record, err := handler.geoLite2Db.City(net.ParseIP(ip))
	if record == nil {
		ioutil.Fatal("query from MaxMind-DB error: record is nil\n")
		return "", ""
	}
	if err != nil {
		ioutil.Fatal("query from MaxMind-DB error: %v\n", err.Error())
		return "", ""
	}

	country := record.Country.Names[languageEn]
	city := record.City.Names[languageEn]
	if city == "" {
		city = cityUnknown
	}

	if strings.EqualFold(countryChina, country) || strings.EqualFold(areaHongKong, country) ||
		strings.EqualFold(areaTaiwan, country) {
		country = fmt.Sprintf("%s %s", record.Country.Names[languageZhCn], country)
		if city != cityUnknown && record.City.Names[languageZhCn] != "" {
			city = fmt.Sprintf("%s %s", record.City.Names[languageZhCn], city)
		}
	} else if strings.EqualFold(countryJapan, country) {
		country = fmt.Sprintf("%s %s", record.Country.Names[languageJa], country)
		if city != cityUnknown && record.City.Names[languageJa] != "" {
			city = fmt.Sprintf("%s %s", record.City.Names[languageJa], city)
		}
	}
	return country, city
}

func (handler *MostVisitedLocationsHandler) cachedQueryIpLocation(ip string) (string, string) {
	data := handler.ipLocationCache.Get(ip)
	if data != nil {
		return data.(*locationEntry).country, data.(*locationEntry).city
	} else { // cache missed
		country, city := handler.queryIpLocation(ip)
		handler.ipLocationCache.Put(ip, &locationEntry{country: country, city: city})
		return country, city
	}
}
