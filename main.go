package main

import (
	"context"
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"illumio-traffic-tool-v2/illumio"

	"github.com/pkg/browser"
)

//go:embed frontend/*.html
var staticFiles embed.FS

type PCEProfile struct {
	Name       string `json:"name"`
	PCEURL     string `json:"pce_url"`
	OrgID      string `json:"org_id"`
	APIKey     string `json:"api_key"`
	APISecret  string `json:"api_secret"`
	SrcLabels  string `json:"src_labels"`
	DstLabels  string `json:"dst_labels"`
	ExcludeSrc string `json:"exclude_src"`
	ExcludeDst string `json:"exclude_dst"`
	Services   string `json:"services"`
	SavePath   string `json:"save_path"`
	FileName   string `json:"file_name"`
	Days       int    `json:"days"`
}

type AppState struct {
	Mu               sync.Mutex
	CompletedDays    int
	RequestedDays    int
	TotalConnections int
	Logs             []string
	IsDone           bool
	IsCancelled      bool
	FileName         string
	Profiles         map[string]PCEProfile
	CancelFunc       context.CancelFunc
	LastSummary      []PortProtocolSummary
	LastInsights     AnalyticsInsights
	DiscoveryCache   *DiscoveryData
	DiscoveryKey     string
}

type PortProtocolSummary struct {
	Port              int    `json:"port"`
	Protocol          string `json:"protocol"`
	ProtocolNumber    int    `json:"protocol_number"`
	FlowCount         int    `json:"flow_count"`
	UniqueConnections int    `json:"unique_connections"`
}

type MatrixSummary struct {
	Source            string `json:"source"`
	Destination       string `json:"destination"`
	FlowCount         int    `json:"flow_count"`
	UniqueConnections int    `json:"unique_connections"`
}

type TalkerSummary struct {
	Name              string `json:"name"`
	FlowCount         int    `json:"flow_count"`
	UniqueConnections int    `json:"unique_connections"`
}

type TrafficCategorySummary struct {
	Name              string `json:"name"`
	FlowCount         int    `json:"flow_count"`
	UniqueConnections int    `json:"unique_connections"`
}

type AnalyticsInsights struct {
	EnvMatrix          []MatrixSummary          `json:"env_matrix"`
	AppMatrix          []MatrixSummary          `json:"app_matrix"`
	TopSourceEnvs      []TalkerSummary          `json:"top_source_envs"`
	TopDestinationEnvs []TalkerSummary          `json:"top_destination_envs"`
	TopSourceIPs       []TalkerSummary          `json:"top_source_ips"`
	TopDestinationIPs  []TalkerSummary          `json:"top_destination_ips"`
	TopAppPairs        []TalkerSummary          `json:"top_app_pairs"`
	TrafficCategories  []TrafficCategorySummary `json:"traffic_categories"`
}

type AnalyticsRecord struct {
	SrcEnv     string
	DstEnv     string
	SrcApp     string
	DstApp     string
	SrcIP      string
	DstIP      string
	DstFQDN    string
	SrcManaged bool
	DstManaged bool
	FlowCount  int
}

type DiscoveryData struct {
	Labels          []illumio.Label
	Services        []illumio.Service
	IPLists         []illumio.IPList
	LabelGroups     []illumio.LabelGroup
	UserGroups      []illumio.UserGroup
	VirtualServices []illumio.VirtualService
	VirtualServers  []illumio.VirtualServer
}

var state = &AppState{
	Logs:     []string{},
	Profiles: make(map[string]PCEProfile),
}

func addLog(msg string) {
	log.Println(msg)
	state.Mu.Lock()
	defer state.Mu.Unlock()
	state.Logs = append(state.Logs, msg)
}

func markRunFinished(fileName string, cancelled bool) {
	state.Mu.Lock()
	defer state.Mu.Unlock()
	state.IsDone = true
	state.IsCancelled = cancelled
	state.FileName = fileName
	state.CancelFunc = nil
}

func discoveryCacheKey(cfg Config) string {
	return strings.Join([]string{
		strings.TrimSpace(cfg.PCEURL),
		strings.TrimSpace(cfg.OrgID),
		strings.TrimSpace(cfg.APIKey),
		strings.TrimSpace(cfg.APISecret),
	}, "|")
}

func fetchDiscoveryData(ctx context.Context, client *illumio.Client, logPrefix string) (DiscoveryData, error) {
	type discoveryTask struct {
		name  string
		fetch func(context.Context) error
	}

	var (
		results  DiscoveryData
		resultMu sync.Mutex
		firstErr error
		errOnce  sync.Once
		cancelFn context.CancelFunc
	)
	ctx, cancelFn = context.WithCancel(ctx)
	defer cancelFn()

	tasks := []discoveryTask{
		{name: "labels", fetch: func(ctx context.Context) error {
			items, err := client.GetLabels(ctx)
			if err == nil {
				resultMu.Lock()
				results.Labels = items
				resultMu.Unlock()
			}
			return err
		}},
		{name: "services", fetch: func(ctx context.Context) error {
			items, err := client.GetServices(ctx)
			if err == nil {
				resultMu.Lock()
				results.Services = items
				resultMu.Unlock()
			}
			return err
		}},
		{name: "IP lists", fetch: func(ctx context.Context) error {
			items, err := client.GetIPLists(ctx)
			if err == nil {
				resultMu.Lock()
				results.IPLists = items
				resultMu.Unlock()
			}
			return err
		}},
		{name: "label groups", fetch: func(ctx context.Context) error {
			items, err := client.GetLabelGroups(ctx)
			if err == nil {
				resultMu.Lock()
				results.LabelGroups = items
				resultMu.Unlock()
			}
			return err
		}},
		{name: "user groups", fetch: func(ctx context.Context) error {
			items, err := client.GetUserGroups(ctx)
			if err == nil {
				resultMu.Lock()
				results.UserGroups = items
				resultMu.Unlock()
			}
			return err
		}},
		{name: "virtual services", fetch: func(ctx context.Context) error {
			items, err := client.GetVirtualServices(ctx)
			if err == nil {
				resultMu.Lock()
				results.VirtualServices = items
				resultMu.Unlock()
			}
			return err
		}},
		{name: "virtual servers", fetch: func(ctx context.Context) error {
			items, err := client.GetVirtualServers(ctx)
			if err == nil {
				resultMu.Lock()
				results.VirtualServers = items
				resultMu.Unlock()
			}
			return err
		}},
	}

	jobs := make(chan discoveryTask)
	var wg sync.WaitGroup
	workerCount := 3

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range jobs {
				if ctx.Err() != nil {
					return
				}

				if logPrefix != "" {
					addLog(fmt.Sprintf("%s loading %s...", logPrefix, task.name))
				}
				if err := task.fetch(ctx); err != nil {
					errOnce.Do(func() {
						firstErr = fmt.Errorf("%s: %w", task.name, err)
						cancelFn()
					})
					return
				}
				if logPrefix != "" {
					count := 0
					resultMu.Lock()
					switch task.name {
					case "labels":
						count = len(results.Labels)
					case "services":
						count = len(results.Services)
					case "IP lists":
						count = len(results.IPLists)
					case "label groups":
						count = len(results.LabelGroups)
					case "user groups":
						count = len(results.UserGroups)
					case "virtual services":
						count = len(results.VirtualServices)
					case "virtual servers":
						count = len(results.VirtualServers)
					}
					resultMu.Unlock()
					addLog(fmt.Sprintf("%s loaded %d %s.", logPrefix, count, task.name))
				}
			}
		}()
	}

	for _, task := range tasks {
		if ctx.Err() != nil {
			break
		}
		jobs <- task
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return DiscoveryData{}, firstErr
	}

	return results, nil
}

func getConfigPath() string {
	ex, _ := os.Executable()
	return filepath.Join(filepath.Dir(ex), "pce_profiles.json")
}

func loadProfiles() {
	path := getConfigPath()
	data, err := os.ReadFile(path)
	if err == nil {
		state.Mu.Lock()
		json.Unmarshal(data, &state.Profiles)
		state.Mu.Unlock()
	}
}

func saveProfiles() {
	state.Mu.Lock()
	data, _ := json.MarshalIndent(state.Profiles, "", "  ")
	state.Mu.Unlock()
	os.WriteFile(getConfigPath(), data, 0644)
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func boolEnvOrDefault(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	switch strings.ToLower(value) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func main() {
	loadProfiles()

	defaultHost := envOrDefault("ITT_HOST", "127.0.0.1")
	defaultPort := envOrDefault("ITT_PORT", "8080")
	defaultOpenBrowser := boolEnvOrDefault("ITT_OPEN_BROWSER", true)

	host := flag.String("host", defaultHost, "Host or interface to bind the web server to")
	port := flag.String("port", defaultPort, "Port to bind the web server to")
	openBrowser := flag.Bool("open-browser", defaultOpenBrowser, "Automatically open the local web UI in a browser")
	flag.Parse()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, _ := staticFiles.ReadFile("frontend/index.html")
		w.Header().Set("Content-Type", "text/html")
		w.Write(data)
	})
	http.HandleFunc("/summary", func(w http.ResponseWriter, r *http.Request) {
		data, _ := staticFiles.ReadFile("frontend/summary.html")
		w.Header().Set("Content-Type", "text/html")
		w.Write(data)
	})
	http.HandleFunc("/executive-summary", func(w http.ResponseWriter, r *http.Request) {
		data, _ := staticFiles.ReadFile("frontend/executive-summary.html")
		w.Header().Set("Content-Type", "text/html")
		w.Write(data)
	})

	http.HandleFunc("/api/test", handleTest)
	http.HandleFunc("/api/discovery", handleDiscovery)
	http.HandleFunc("/api/start", handleStart)
	http.HandleFunc("/api/cancel", handleCancel)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/results/summary", handleSummary)
	http.HandleFunc("/api/results/import-csv", handleImportCSV)

	http.HandleFunc("/api/profiles/get", func(w http.ResponseWriter, r *http.Request) {
		state.Mu.Lock()
		json.NewEncoder(w).Encode(state.Profiles)
		state.Mu.Unlock()
	})
	http.HandleFunc("/api/profiles/save", handleSaveProfile)
	http.HandleFunc("/api/profiles/delete", handleDeleteProfile)

	listenAddr := fmt.Sprintf("%s:%s", *host, *port)
	localURL := fmt.Sprintf("http://localhost:%s", *port)

	fmt.Printf("Starting Illumio Traffic Tool on %s\n", listenAddr)
	fmt.Printf("Local access URL: %s\n", localURL)
	if *host == "0.0.0.0" || *host == "::" {
		fmt.Printf("Remote access URL: http://<server-ip-or-dns>:%s\n", *port)
	} else if *host != "127.0.0.1" && *host != "localhost" {
		fmt.Printf("Configured access URL: http://%s:%s\n", *host, *port)
	}
	if *openBrowser {
		go func() {
			time.Sleep(1 * time.Second)
			browser.OpenURL(localURL)
		}()
	}

	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

func handleDiscovery(w http.ResponseWriter, r *http.Request) {
	var cfg Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	const discoveryTimeout = 15 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
	defer cancel()

	client := illumio.NewClient(cfg.PCEURL, cfg.OrgID, cfg.APIKey, cfg.APISecret)
	addLog("Discovery: starting parallel collection load (up to 3 collection jobs at a time)...")
	discoveryData, err := fetchDiscoveryData(ctx, client, "Discovery:")
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			err = fmt.Errorf("discovery timed out after %s while loading large policy collections; no new discovery cache was saved", discoveryTimeout)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	labelNames := make([]string, 0, len(discoveryData.Labels))
	for _, item := range discoveryData.Labels {
		labelNames = append(labelNames, item.Value)
	}
	serviceNames := make([]string, 0, len(discoveryData.Services))
	for _, item := range discoveryData.Services {
		serviceNames = append(serviceNames, item.Name)
	}
	ipListNames := make([]string, 0, len(discoveryData.IPLists))
	for _, item := range discoveryData.IPLists {
		ipListNames = append(ipListNames, item.Name)
	}
	lgNames := make([]string, 0, len(discoveryData.LabelGroups))
	for _, item := range discoveryData.LabelGroups {
		lgNames = append(lgNames, item.Name)
	}
	ugNames := make([]string, 0, len(discoveryData.UserGroups))
	for _, item := range discoveryData.UserGroups {
		ugNames = append(ugNames, item.Name)
	}
	vsNames := make([]string, 0, len(discoveryData.VirtualServices))
	for _, item := range discoveryData.VirtualServices {
		vsNames = append(vsNames, item.Name)
	}
	vsvrNames := make([]string, 0, len(discoveryData.VirtualServers))
	for _, item := range discoveryData.VirtualServers {
		vsvrNames = append(vsvrNames, item.Name)
	}

	state.Mu.Lock()
	state.DiscoveryCache = &discoveryData
	state.DiscoveryKey = discoveryCacheKey(cfg)
	state.Mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":         true,
		"labels":          labelNames,
		"services":        serviceNames,
		"ipLists":         ipListNames,
		"labelGroups":     lgNames,
		"userGroups":      ugNames,
		"virtualServices": vsNames,
		"virtualServers":  vsvrNames,
	})
}

func handleCancel(w http.ResponseWriter, r *http.Request) {
	var cancel context.CancelFunc
	state.Mu.Lock()
	if state.CancelFunc != nil {
		cancel = state.CancelFunc
		state.IsCancelled = true
	}
	state.Mu.Unlock()
	if cancel != nil {
		cancel()
		addLog("!!! CANCEL SIGNAL RECEIVED !!!")
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handleSaveProfile(w http.ResponseWriter, r *http.Request) {
	var prof PCEProfile
	json.NewDecoder(r.Body).Decode(&prof)
	if prof.Name == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Profile name required"})
		return
	}
	state.Mu.Lock()
	state.Profiles[prof.Name] = prof
	state.Mu.Unlock()
	saveProfiles()
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	state.Mu.Lock()
	delete(state.Profiles, req.Name)
	state.Mu.Unlock()
	saveProfiles()
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

type Config struct {
	PCEURL     string `json:"pce_url"`
	OrgID      string `json:"org_id"`
	APIKey     string `json:"api_key"`
	APISecret  string `json:"api_secret"`
	SrcLabels  string `json:"src_labels"`
	DstLabels  string `json:"dst_labels"`
	ExcludeSrc string `json:"exclude_src"`
	ExcludeDst string `json:"exclude_dst"`
	Services   string `json:"services"`
	SavePath   string `json:"save_path"`
	FileName   string `json:"file_name"`
	Days       int    `json:"days"`
}

func handleTest(w http.ResponseWriter, r *http.Request) {
	var cfg Config
	json.NewDecoder(r.Body).Decode(&cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	client := illumio.NewClient(cfg.PCEURL, cfg.OrgID, cfg.APIKey, cfg.APISecret)
	err := client.TestConnection(ctx)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	state.Mu.Lock()
	defer state.Mu.Unlock()

	response := map[string]interface{}{
		"completedDays":    state.CompletedDays,
		"requestedDays":    state.RequestedDays,
		"totalConnections": state.TotalConnections,
		"newLogs":          state.Logs,
		"done":             state.IsDone,
		"cancelled":        state.IsCancelled,
		"fileName":         state.FileName,
	}
	state.Logs = []string{}
	json.NewEncoder(w).Encode(response)
}

func handleSummary(w http.ResponseWriter, r *http.Request) {
	state.Mu.Lock()
	defer state.Mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  state.FileName != "" && len(state.LastSummary) > 0,
		"fileName": state.FileName,
		"summary":  state.LastSummary,
		"insights": state.LastInsights,
	})
}

type csvAnalyticsRow struct {
	SrcEnv            string
	DstEnv            string
	SrcApp            string
	DstApp            string
	SrcIP             string
	DstEndpoint       string
	Port              int
	Protocol          string
	ProtocolNumber    int
	FlowCount         int
	UniqueConnections int
	SrcManaged        bool
	DstManaged        bool
}

func normalizeCSVValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return trimmed
	}
	switch trimmed {
	case "No Env Label", "No App Label":
		return trimmed
	default:
		return trimmed
	}
}

func protocolNumberFromName(value string) int {
	protoMap := map[string]int{
		"ICMP":   1,
		"IGMP":   2,
		"TCP":    6,
		"UDP":    17,
		"GRE":    47,
		"ESP":    50,
		"AH":     51,
		"ICMPV6": 58,
		"OSPF":   89,
		"VRRP":   112,
		"SCTP":   132,
	}
	if number, ok := protoMap[strings.ToUpper(strings.TrimSpace(value))]; ok {
		return number
	}
	return 0
}

func parseCSVAnalytics(reader io.Reader) ([]PortProtocolSummary, AnalyticsInsights, error) {
	csvReader := csv.NewReader(reader)
	rows, err := csvReader.ReadAll()
	if err != nil {
		return nil, AnalyticsInsights{}, err
	}
	if len(rows) < 1 {
		return nil, AnalyticsInsights{}, fmt.Errorf("CSV is empty")
	}

	headerIndex := make(map[string]int)
	for i, header := range rows[0] {
		headerIndex[strings.TrimSpace(header)] = i
	}

	requiredHeaders := []string{"Source IP", "Destination IP", "Port", "Protocol", "Flows"}
	for _, header := range requiredHeaders {
		if _, ok := headerIndex[header]; !ok {
			return nil, AnalyticsInsights{}, fmt.Errorf("CSV is missing required header: %s", header)
		}
	}

	getValue := func(row []string, header string) string {
		index, ok := headerIndex[header]
		if !ok || index >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[index])
	}

	summary := []PortProtocolSummary{}
	records := []AnalyticsRecord{}
	for _, row := range rows[1:] {
		if len(row) == 0 {
			continue
		}

		flowCount := 0
		fmt.Sscanf(getValue(row, "Flows"), "%d", &flowCount)
		port := 0
		fmt.Sscanf(getValue(row, "Port"), "%d", &port)
		protocol := getValue(row, "Protocol")
		protoNumber := protocolNumberFromName(protocol)
		if protoNumber == 0 {
			fmt.Sscanf(protocol, "%d", &protoNumber)
		}

		srcEnv := normalizeCSVValue(getValue(row, "Src Env"))
		if srcEnv == "" {
			srcEnv = "External/Unmanaged"
		}
		dstEnv := normalizeCSVValue(getValue(row, "Dst Env"))
		if dstEnv == "" {
			dstEnv = "External/Unmanaged"
		}
		srcApp := normalizeCSVValue(getValue(row, "Src App"))
		if srcApp == "" {
			srcApp = "External/Unmanaged"
		}
		dstApp := normalizeCSVValue(getValue(row, "Dst App"))
		if dstApp == "" {
			dstApp = "External/Unmanaged"
		}

		dstEndpoint := getValue(row, "Destination IP")
		if fqdn := getValue(row, "FQDN"); fqdn != "" {
			dstEndpoint = fqdn
		}

		summary = append(summary, PortProtocolSummary{
			Port:              port,
			Protocol:          protocol,
			ProtocolNumber:    protoNumber,
			FlowCount:         flowCount,
			UniqueConnections: 1,
		})
		records = append(records, AnalyticsRecord{
			SrcEnv:     srcEnv,
			DstEnv:     dstEnv,
			SrcApp:     srcApp,
			DstApp:     dstApp,
			SrcIP:      getValue(row, "Source IP"),
			DstIP:      dstEndpoint,
			SrcManaged: srcEnv != "External/Unmanaged" || srcApp != "External/Unmanaged",
			DstManaged: dstEnv != "External/Unmanaged" || dstApp != "External/Unmanaged",
			FlowCount:  flowCount,
		})
	}

	portSummaryMap := make(map[string]PortProtocolSummary)
	for _, item := range summary {
		key := fmt.Sprintf("%s:%d", item.Protocol, item.Port)
		entry := portSummaryMap[key]
		entry.Port = item.Port
		entry.Protocol = item.Protocol
		entry.ProtocolNumber = item.ProtocolNumber
		entry.FlowCount += item.FlowCount
		entry.UniqueConnections += item.UniqueConnections
		portSummaryMap[key] = entry
	}

	finalSummary := make([]PortProtocolSummary, 0, len(portSummaryMap))
	for _, item := range portSummaryMap {
		finalSummary = append(finalSummary, item)
	}
	sort.Slice(finalSummary, func(i, j int) bool {
		if finalSummary[i].FlowCount != finalSummary[j].FlowCount {
			return finalSummary[i].FlowCount > finalSummary[j].FlowCount
		}
		if finalSummary[i].Port != finalSummary[j].Port {
			return finalSummary[i].Port < finalSummary[j].Port
		}
		return finalSummary[i].Protocol < finalSummary[j].Protocol
	})

	return finalSummary, buildInsights(records), nil
}

func handleImportCSV(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "CSV file is required"})
		return
	}
	defer file.Close()

	summary, insights, err := parseCSVAnalytics(file)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	state.Mu.Lock()
	state.LastSummary = summary
	state.LastInsights = insights
	state.FileName = "Imported CSV: " + header.Filename
	state.IsDone = true
	state.IsCancelled = false
	state.Mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"fileName": state.FileName,
	})
}

func handleStart(w http.ResponseWriter, r *http.Request) {
	var cfg Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	if cfg.Days <= 0 {
		cfg.Days = 90
	}

	state.Mu.Lock()
	state.CompletedDays = 0
	state.RequestedDays = cfg.Days
	state.TotalConnections = 0
	state.IsDone = false
	state.IsCancelled = false
	state.Logs = []string{}
	state.FileName = ""
	state.LastSummary = nil
	state.LastInsights = AnalyticsInsights{}

	ctx, cancel := context.WithCancel(context.Background())
	state.CancelFunc = cancel
	state.Mu.Unlock()

	addLog("Starting extraction...")
	go runExtraction(ctx, cfg)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func looksLikeIPAddress(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if ip := net.ParseIP(value); ip != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return true
	}
	return false
}

func parseSelector(token string, labelMap, ipListMap, lgMap, ugMap, vsMap, vsvrMap map[string]string) (illumio.LabelRef, bool) {
	name := strings.TrimSpace(token)
	if name == "" {
		return illumio.LabelRef{}, false
	}

	ref := illumio.LabelRef{}
	switch {
	case labelMap[name] != "":
		ref.Label = &illumio.Href{Href: labelMap[name]}
	case ipListMap[name] != "":
		ref.IPList = &illumio.Href{Href: ipListMap[name]}
	case lgMap[name] != "":
		ref.LabelGroup = &illumio.Href{Href: lgMap[name]}
	case ugMap[name] != "":
		ref.UserGroup = &illumio.Href{Href: ugMap[name]}
	case vsMap[name] != "":
		ref.VirtualService = &illumio.Href{Href: vsMap[name]}
	case vsvrMap[name] != "":
		ref.VirtualServer = &illumio.Href{Href: vsvrMap[name]}
	default:
		if !looksLikeIPAddress(name) {
			return illumio.LabelRef{}, false
		}
		ref.IPAddress = name
	}

	return ref, true
}

func buildIncludeGroups(raw string, labelMap, labelKeyMap, ipListMap, lgMap, ugMap, vsMap, vsvrMap map[string]string) ([][]illumio.LabelRef, []string) {
	groupsByKey := make(map[string][]illumio.LabelRef)
	ipGroup := []illumio.LabelRef{}
	groupOrder := []string{}
	warnings := []string{}

	for _, token := range strings.Split(raw, ",") {
		ref, ok := parseSelector(token, labelMap, ipListMap, lgMap, ugMap, vsMap, vsvrMap)
		if !ok {
			if trimmed := strings.TrimSpace(token); trimmed != "" {
				warnings = append(warnings, trimmed)
			}
			continue
		}

		groupKey := "ip_address"
		switch {
		case ref.Label != nil:
			if key := labelKeyMap[strings.TrimSpace(token)]; key != "" {
				groupKey = "label_key:" + strings.ToLower(key)
			} else {
				groupKey = "label:" + ref.Label.Href
			}
		case ref.LabelGroup != nil:
			groupKey = "label_group"
		case ref.IPList != nil:
			groupKey = "ip_list"
		case ref.UserGroup != nil:
			groupKey = "user_group"
		case ref.VirtualService != nil:
			groupKey = "virtual_service"
		case ref.VirtualServer != nil:
			groupKey = "virtual_server"
		}

		if groupKey == "ip_address" {
			ipGroup = append(ipGroup, ref)
			continue
		}
		if _, exists := groupsByKey[groupKey]; !exists {
			groupOrder = append(groupOrder, groupKey)
		}
		groupsByKey[groupKey] = append(groupsByKey[groupKey], ref)
	}

	groups := make([][]illumio.LabelRef, 0, len(groupOrder)+1)
	for _, key := range groupOrder {
		groups = append(groups, groupsByKey[key])
	}
	if len(ipGroup) > 0 {
		groups = append(groups, ipGroup)
	}

	return groups, warnings
}

func buildExcludeRefs(raw string, labelMap, ipListMap, lgMap, ugMap, vsMap, vsvrMap map[string]string) ([]illumio.LabelRef, []string) {
	refs := []illumio.LabelRef{}
	warnings := []string{}
	for _, token := range strings.Split(raw, ",") {
		ref, ok := parseSelector(token, labelMap, ipListMap, lgMap, ugMap, vsMap, vsvrMap)
		if ok {
			refs = append(refs, ref)
		} else if trimmed := strings.TrimSpace(token); trimmed != "" {
			warnings = append(warnings, trimmed)
		}
	}
	return refs, warnings
}

func parseProtocolNumber(raw string) (int, bool) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "TCP":
		return 6, true
	case "UDP":
		return 17, true
	case "ICMP":
		return 1, true
	case "IGMP":
		return 2, true
	case "GRE":
		return 47, true
	}

	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 0 || value > 255 {
		return 0, false
	}
	return value, true
}

func parseDirectService(entry string) (illumio.PortProtoService, bool) {
	parts := strings.SplitN(entry, ":", 2)
	if len(parts) != 2 {
		return illumio.PortProtoService{}, false
	}

	proto, ok := parseProtocolNumber(parts[0])
	if !ok {
		return illumio.PortProtoService{}, false
	}

	portSpec := strings.TrimSpace(parts[1])
	if portSpec == "" {
		return illumio.PortProtoService{}, false
	}

	service := illumio.PortProtoService{Proto: proto}
	if strings.Contains(portSpec, "-") {
		rangeParts := strings.SplitN(portSpec, "-", 2)
		if len(rangeParts) != 2 {
			return illumio.PortProtoService{}, false
		}

		startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
		if err != nil || startPort < 1 || startPort > 65535 {
			return illumio.PortProtoService{}, false
		}

		endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
		if err != nil || endPort < startPort || endPort > 65535 {
			return illumio.PortProtoService{}, false
		}

		service.Port = startPort
		service.ToPort = endPort
		return service, true
	}

	port, err := strconv.Atoi(portSpec)
	if err != nil || port < 1 || port > 65535 {
		return illumio.PortProtoService{}, false
	}

	service.Port = port
	return service, true
}

func buildServiceIncludeEntries(raw string, serviceMap map[string]string) ([]interface{}, []string) {
	includes := make([]interface{}, 0)
	warnings := make([]string, 0)

	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if href, ok := serviceMap[entry]; ok {
			includes = append(includes, illumio.ServiceRef{Href: href})
			continue
		}
		if directService, ok := parseDirectService(entry); ok {
			includes = append(includes, directService)
			continue
		}
		warnings = append(warnings, entry)
	}

	return includes, warnings
}

func uniqueJoinedLabelValues(labels []illumio.FlowLabel, key string) string {
	seen := make(map[string]bool)
	values := []string{}
	for _, label := range labels {
		if strings.EqualFold(label.Key, key) {
			if !seen[label.Value] {
				seen[label.Value] = true
				values = append(values, label.Value)
			}
		}
	}
	if len(values) == 0 {
		return ""
	}
	sort.Strings(values)
	return strings.Join(values, ", ")
}

func managedLabelValue(labels []illumio.FlowLabel, key string) string {
	value := uniqueJoinedLabelValues(labels, key)
	if value == "" {
		return "No " + strings.ToUpper(key[:1]) + key[1:] + " Label"
	}
	return value
}

func endpointHasClassification(flow illumio.TrafficFlow, isSource bool) bool {
	if isSource {
		return flow.SrcWorkloadHref != "" || len(flow.SrcLabels) > 0
	}
	return flow.DstWorkloadHref != "" || len(flow.DstLabels) > 0
}

func externalOrManagedLabel(flow illumio.TrafficFlow, isSource bool, key string) string {
	var labels []illumio.FlowLabel
	if isSource {
		labels = flow.SrcLabels
	} else {
		labels = flow.DstLabels
	}
	if len(labels) == 0 && !endpointHasClassification(flow, isSource) {
		return "External/Unmanaged"
	}
	return managedLabelValue(labels, key)
}

func endpointDisplayName(flow illumio.TrafficFlow, isSource bool) string {
	if isSource {
		if flow.SrcIP != "" {
			return flow.SrcIP
		}
		if flow.SrcWorkloadHref != "" {
			return flow.SrcWorkloadHref
		}
		return "Unknown Source"
	}
	if flow.DstIP != "" {
		return flow.DstIP
	}
	if flow.DstFQDN != "" {
		return flow.DstFQDN
	}
	if flow.DstWorkloadHref != "" {
		return flow.DstWorkloadHref
	}
	return "Unknown Destination"
}

func topTalkersFromMap(items map[string]TalkerSummary, limit int) []TalkerSummary {
	results := make([]TalkerSummary, 0, len(items))
	for _, item := range items {
		results = append(results, item)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].FlowCount != results[j].FlowCount {
			return results[i].FlowCount > results[j].FlowCount
		}
		return results[i].Name < results[j].Name
	})
	if len(results) > limit {
		results = results[:limit]
	}
	return results
}

func matrixFromMap(items map[string]MatrixSummary) []MatrixSummary {
	results := make([]MatrixSummary, 0, len(items))
	for _, item := range items {
		results = append(results, item)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].FlowCount != results[j].FlowCount {
			return results[i].FlowCount > results[j].FlowCount
		}
		if results[i].Source != results[j].Source {
			return results[i].Source < results[j].Source
		}
		return results[i].Destination < results[j].Destination
	})
	return results
}

func categoryList(items map[string]TrafficCategorySummary) []TrafficCategorySummary {
	results := make([]TrafficCategorySummary, 0, len(items))
	for _, item := range items {
		results = append(results, item)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].FlowCount != results[j].FlowCount {
			return results[i].FlowCount > results[j].FlowCount
		}
		return results[i].Name < results[j].Name
	})
	return results
}

func buildInsights(records []AnalyticsRecord) AnalyticsInsights {
	envMatrixMap := make(map[string]MatrixSummary)
	appMatrixMap := make(map[string]MatrixSummary)
	topSourceEnvMap := make(map[string]TalkerSummary)
	topDestinationEnvMap := make(map[string]TalkerSummary)
	topSourceIPMap := make(map[string]TalkerSummary)
	topDestinationIPMap := make(map[string]TalkerSummary)
	topAppPairMap := make(map[string]TalkerSummary)
	categoryMap := make(map[string]TrafficCategorySummary)

	for _, record := range records {
		envKey := record.SrcEnv + "->" + record.DstEnv
		envEntry := envMatrixMap[envKey]
		envEntry.Source = record.SrcEnv
		envEntry.Destination = record.DstEnv
		envEntry.FlowCount += record.FlowCount
		envEntry.UniqueConnections++
		envMatrixMap[envKey] = envEntry

		appKey := record.SrcApp + "->" + record.DstApp
		appEntry := appMatrixMap[appKey]
		appEntry.Source = record.SrcApp
		appEntry.Destination = record.DstApp
		appEntry.FlowCount += record.FlowCount
		appEntry.UniqueConnections++
		appMatrixMap[appKey] = appEntry

		srcEnvEntry := topSourceEnvMap[record.SrcEnv]
		srcEnvEntry.Name = record.SrcEnv
		srcEnvEntry.FlowCount += record.FlowCount
		srcEnvEntry.UniqueConnections++
		topSourceEnvMap[record.SrcEnv] = srcEnvEntry

		dstEnvEntry := topDestinationEnvMap[record.DstEnv]
		dstEnvEntry.Name = record.DstEnv
		dstEnvEntry.FlowCount += record.FlowCount
		dstEnvEntry.UniqueConnections++
		topDestinationEnvMap[record.DstEnv] = dstEnvEntry

		srcIPEntry := topSourceIPMap[record.SrcIP]
		srcIPEntry.Name = record.SrcIP
		srcIPEntry.FlowCount += record.FlowCount
		srcIPEntry.UniqueConnections++
		topSourceIPMap[record.SrcIP] = srcIPEntry

		dstEndpoint := record.DstIP
		dstIPEntry := topDestinationIPMap[dstEndpoint]
		dstIPEntry.Name = dstEndpoint
		dstIPEntry.FlowCount += record.FlowCount
		dstIPEntry.UniqueConnections++
		topDestinationIPMap[dstEndpoint] = dstIPEntry

		appPairName := record.SrcApp + " -> " + record.DstApp
		appPairEntry := topAppPairMap[appPairName]
		appPairEntry.Name = appPairName
		appPairEntry.FlowCount += record.FlowCount
		appPairEntry.UniqueConnections++
		topAppPairMap[appPairName] = appPairEntry

		categoryName := "Internal -> Internal"
		switch {
		case record.SrcManaged && !record.DstManaged:
			categoryName = "Internal -> External/Unmanaged"
		case !record.SrcManaged && record.DstManaged:
			categoryName = "External/Unmanaged -> Internal"
		case !record.SrcManaged && !record.DstManaged:
			categoryName = "External/Unmanaged -> External/Unmanaged"
		}
		categoryEntry := categoryMap[categoryName]
		categoryEntry.Name = categoryName
		categoryEntry.FlowCount += record.FlowCount
		categoryEntry.UniqueConnections++
		categoryMap[categoryName] = categoryEntry
	}

	return AnalyticsInsights{
		EnvMatrix:          matrixFromMap(envMatrixMap),
		AppMatrix:          matrixFromMap(appMatrixMap),
		TopSourceEnvs:      topTalkersFromMap(topSourceEnvMap, 12),
		TopDestinationEnvs: topTalkersFromMap(topDestinationEnvMap, 12),
		TopSourceIPs:       topTalkersFromMap(topSourceIPMap, 12),
		TopDestinationIPs:  topTalkersFromMap(topDestinationIPMap, 12),
		TopAppPairs:        topTalkersFromMap(topAppPairMap, 15),
		TrafficCategories:  categoryList(categoryMap),
	}
}

func runExtraction(ctx context.Context, cfg Config) {
	client := illumio.NewClient(cfg.PCEURL, cfg.OrgID, cfg.APIKey, cfg.APISecret)
	var discoveryData DiscoveryData
	cacheKey := discoveryCacheKey(cfg)
	state.Mu.Lock()
	if state.DiscoveryCache != nil && state.DiscoveryKey == cacheKey {
		discoveryData = *state.DiscoveryCache
	}
	state.Mu.Unlock()

	if len(discoveryData.Labels) == 0 {
		addLog("Extraction: loading policy objects for request building...")
		fetchedDiscovery, err := fetchDiscoveryData(ctx, client, "Extraction discovery:")
		if err != nil {
			addLog(fmt.Sprintf("Error: %v", err))
			markRunFinished("", ctx.Err() != nil)
			return
		}
		discoveryData = fetchedDiscovery
		state.Mu.Lock()
		state.DiscoveryCache = &fetchedDiscovery
		state.DiscoveryKey = cacheKey
		state.Mu.Unlock()
	} else {
		addLog("Extraction: using cached discovery objects from the last policy-object load.")
	}

	allLabels := discoveryData.Labels
	allServices := discoveryData.Services
	allIPLists := discoveryData.IPLists
	allLabelGroups := discoveryData.LabelGroups
	allUserGroups := discoveryData.UserGroups
	allVServices := discoveryData.VirtualServices
	allVServers := discoveryData.VirtualServers

	labelMap := make(map[string]string)
	labelKeyMap := make(map[string]string)
	uniqueKeys := make(map[string]bool)
	for _, l := range allLabels {
		labelMap[l.Value] = l.Href
		labelKeyMap[l.Value] = l.Key
		if l.Key != "" {
			uniqueKeys[l.Key] = true
		}
	}

	standard := []string{"role", "app", "env", "loc"}
	orderedKeys := []string{}
	for _, k := range standard {
		if uniqueKeys[k] {
			orderedKeys = append(orderedKeys, k)
			delete(uniqueKeys, k)
		}
	}
	for k := range uniqueKeys {
		orderedKeys = append(orderedKeys, k)
	}

	serviceMap := make(map[string]string)
	for _, s := range allServices {
		serviceMap[s.Name] = s.Href
	}
	ipListMap := make(map[string]string)
	for _, i := range allIPLists {
		ipListMap[i.Name] = i.Href
	}
	lgMap := make(map[string]string)
	for _, i := range allLabelGroups {
		lgMap[i.Name] = i.Href
	}
	ugMap := make(map[string]string)
	for _, i := range allUserGroups {
		ugMap[i.Name] = i.Href
	}
	vsMap := make(map[string]string)
	for _, i := range allVServices {
		vsMap[i.Name] = i.Href
	}
	vsvrMap := make(map[string]string)
	for _, i := range allVServers {
		vsvrMap[i.Name] = i.Href
	}

	req := illumio.AsyncQueryRequest{
		Sources: illumio.IncludeExclude{
			Include: [][]illumio.LabelRef{},
			Exclude: []illumio.LabelRef{},
		},
		Destinations: illumio.IncludeExclude{
			Include: [][]illumio.LabelRef{},
			Exclude: []illumio.LabelRef{},
		},
		Services: illumio.ServiceFilter{
			Include: make([]interface{}, 0),
			Exclude: make([]interface{}, 0),
		},
	}

	var selectorWarnings []string
	req.Sources.Include, selectorWarnings = buildIncludeGroups(cfg.SrcLabels, labelMap, labelKeyMap, ipListMap, lgMap, ugMap, vsMap, vsvrMap)
	for _, warning := range selectorWarnings {
		addLog(fmt.Sprintf("Warning: skipped unknown source selector '%s'", warning))
	}
	req.Destinations.Include, selectorWarnings = buildIncludeGroups(cfg.DstLabels, labelMap, labelKeyMap, ipListMap, lgMap, ugMap, vsMap, vsvrMap)
	for _, warning := range selectorWarnings {
		addLog(fmt.Sprintf("Warning: skipped unknown destination selector '%s'", warning))
	}
	req.Sources.Exclude, selectorWarnings = buildExcludeRefs(cfg.ExcludeSrc, labelMap, ipListMap, lgMap, ugMap, vsMap, vsvrMap)
	for _, warning := range selectorWarnings {
		addLog(fmt.Sprintf("Warning: skipped unknown source exclusion '%s'", warning))
	}
	req.Destinations.Exclude, selectorWarnings = buildExcludeRefs(cfg.ExcludeDst, labelMap, ipListMap, lgMap, ugMap, vsMap, vsvrMap)
	for _, warning := range selectorWarnings {
		addLog(fmt.Sprintf("Warning: skipped unknown destination exclusion '%s'", warning))
	}

	if cfg.Services != "" {
		includeEntries, warnings := buildServiceIncludeEntries(cfg.Services, serviceMap)
		req.Services.Include = append(req.Services.Include, includeEntries...)
		for _, entry := range warnings {
			addLog(fmt.Sprintf("Warning: skipped unknown service filter '%s'", entry))
		}
	}

	type FlowKey struct {
		SrcIP, DstIP     string
		Port, Proto      int
		SrcWkld, DstWkld string
		Process, FQDN    string
	}
	aggregatedFlows := make(map[FlowKey]struct {
		TotalCount          int
		FirstSeen, LastSeen time.Time
		Raw                 illumio.TrafficFlow
	})
	var aggMu sync.Mutex

	now := time.Now().UTC()
	jobs := make(chan int, cfg.Days)
	var wg sync.WaitGroup
	for w := 1; w <= 3; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for day := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					dayReq := req
					dayReq.EndDate = now.AddDate(0, 0, -day).Format("2006-01-02T00:00:00Z")
					dayReq.StartDate = now.AddDate(0, 0, -(day + 1)).Format("2006-01-02T00:00:00Z")
					flows, err := client.FetchDayOfTraffic(ctx, dayReq, addLog)
					if err == nil {
						aggMu.Lock()
						for _, f := range flows {
							key := FlowKey{f.SrcIP, f.DstIP, f.DstPort, f.Proto, f.SrcWorkloadHref, f.DstWorkloadHref, f.ProcessName, f.DstFQDN}
							entry, exists := aggregatedFlows[key]
							if !exists {
								entry.FirstSeen = f.Timestamp
								entry.LastSeen = f.Timestamp
								entry.Raw = f
							}
							entry.TotalCount += f.NumConnections
							if f.Timestamp.Before(entry.FirstSeen) {
								entry.FirstSeen = f.Timestamp
							}
							if f.Timestamp.After(entry.LastSeen) {
								entry.LastSeen = f.Timestamp
							}
							aggregatedFlows[key] = entry
						}
						state.Mu.Lock()
						state.CompletedDays++
						state.TotalConnections = len(aggregatedFlows)
						state.Mu.Unlock()
						aggMu.Unlock()
						addLog(fmt.Sprintf("Day -%d: %d connections gathered", day, len(flows)))
					} else {
						addLog(fmt.Sprintf("Error Day -%d: %v", day, err))
					}
				}
			}
		}()
	}
	for i := 0; i < cfg.Days; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	if ctx.Err() != nil {
		markRunFinished("", true)
		return
	}

	finalName := cfg.FileName
	if finalName == "" {
		finalName = fmt.Sprintf("BT_%s.csv", time.Now().Format("20060102_150405"))
	}
	if !strings.HasSuffix(strings.ToLower(finalName), ".csv") {
		finalName += ".csv"
	}
	finalPath := finalName
	if cfg.SavePath != "" {
		finalPath = filepath.Join(cfg.SavePath, finalName)
	}

	f, err := os.Create(finalPath)
	if err != nil {
		addLog(fmt.Sprintf("Error: %v", err))
		markRunFinished("", false)
		return
	}
	defer f.Close()

	w := csv.NewWriter(f)

	// Reordered Header
	header := []string{"First Detected", "Last Detected", "Source IP"}
	for _, k := range orderedKeys {
		header = append(header, "Src "+strings.ToUpper(k[:1])+k[1:])
	}
	header = append(header, "Destination IP")
	for _, k := range orderedKeys {
		header = append(header, "Dst "+strings.ToUpper(k[:1])+k[1:])
	}
	header = append(header, "FQDN", "Port", "Protocol", "Process Name", "Flows")
	w.Write(header)

	protoMap := map[int]string{1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 112: "VRRP", 132: "SCTP"}
	summaryMap := make(map[string]PortProtocolSummary)
	analyticsRecords := make([]AnalyticsRecord, 0, len(aggregatedFlows))
	for _, entry := range aggregatedFlows {
		flow := entry.Raw
		protocol := fmt.Sprintf("%d", flow.Proto)
		if name, ok := protoMap[flow.Proto]; ok {
			protocol = name
		}
		srcL := make(map[string][]string)
		for _, l := range flow.SrcLabels {
			srcL[l.Key] = append(srcL[l.Key], l.Value)
		}
		dstL := make(map[string][]string)
		for _, l := range flow.DstLabels {
			dstL[l.Key] = append(dstL[l.Key], l.Value)
		}

		row := []string{
			entry.FirstSeen.Format("2006-01-02 15:04:05"),
			entry.LastSeen.Format("2006-01-02 15:04:05"),
			flow.SrcIP,
		}
		// Source Labels
		for _, k := range orderedKeys {
			row = append(row, strings.Join(srcL[k], ", "))
		}
		// Destination IP
		row = append(row, flow.DstIP)
		// Destination Labels
		for _, k := range orderedKeys {
			row = append(row, strings.Join(dstL[k], ", "))
		}
		// Final metadata
		row = append(row,
			flow.DstFQDN,
			fmt.Sprintf("%d", flow.DstPort),
			protocol,
			flow.ProcessName,
			fmt.Sprintf("%d", entry.TotalCount),
		)
		w.Write(row)

		summaryKey := fmt.Sprintf("%s:%d", protocol, flow.DstPort)
		summaryEntry := summaryMap[summaryKey]
		summaryEntry.Port = flow.DstPort
		summaryEntry.Protocol = protocol
		summaryEntry.ProtocolNumber = flow.Proto
		summaryEntry.FlowCount += entry.TotalCount
		summaryEntry.UniqueConnections++
		summaryMap[summaryKey] = summaryEntry

		analyticsRecords = append(analyticsRecords, AnalyticsRecord{
			SrcEnv:     externalOrManagedLabel(flow, true, "env"),
			DstEnv:     externalOrManagedLabel(flow, false, "env"),
			SrcApp:     externalOrManagedLabel(flow, true, "app"),
			DstApp:     externalOrManagedLabel(flow, false, "app"),
			SrcIP:      endpointDisplayName(flow, true),
			DstIP:      endpointDisplayName(flow, false),
			DstFQDN:    flow.DstFQDN,
			SrcManaged: endpointHasClassification(flow, true),
			DstManaged: endpointHasClassification(flow, false),
			FlowCount:  entry.TotalCount,
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		addLog(fmt.Sprintf("Error writing CSV: %v", err))
		markRunFinished("", false)
		return
	}

	summary := make([]PortProtocolSummary, 0, len(summaryMap))
	for _, item := range summaryMap {
		summary = append(summary, item)
	}
	sort.Slice(summary, func(i, j int) bool {
		if summary[i].FlowCount != summary[j].FlowCount {
			return summary[i].FlowCount > summary[j].FlowCount
		}
		if summary[i].Port != summary[j].Port {
			return summary[i].Port < summary[j].Port
		}
		return summary[i].Protocol < summary[j].Protocol
	})

	state.Mu.Lock()
	state.LastSummary = summary
	state.LastInsights = buildInsights(analyticsRecords)
	state.Mu.Unlock()

	addLog(fmt.Sprintf("SUCCESS: Final data saved to %s", finalPath))
	markRunFinished(finalPath, false)
}
