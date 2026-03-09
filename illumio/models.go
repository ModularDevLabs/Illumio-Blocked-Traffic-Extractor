package illumio

import "time"

type Label struct {
	Href  string `json:"href"`
	Value string `json:"value"`
	Key   string `json:"key"`
}

type Service struct {
	Href string `json:"href"`
	Name string `json:"name"`
}

type IPList struct {
	Href string `json:"href"`
	Name string `json:"name"`
}

type LabelGroup struct {
	Href string `json:"href"`
	Name string `json:"name"`
}

type UserGroup struct {
	Href string `json:"href"`
	Name string `json:"name"`
}

type VirtualService struct {
	Href string `json:"href"`
	Name string `json:"name"`
}

type VirtualServer struct {
	Href string `json:"href"`
	Name string `json:"name"`
}

type FlowLabel struct {
	Href  string `json:"href"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

type TrafficFlow struct {
	SrcIP          string      `json:"src_ip"`
	DstIP          string      `json:"dst_ip"`
	Proto          int         `json:"proto"`
	DstPort        int         `json:"dst_port"`
	NumConnections int         `json:"num_connections"`
	Timestamp      time.Time   `json:"timestamp"`
	SrcLabels      []FlowLabel `json:"src_labels"`
	DstLabels      []FlowLabel `json:"dst_labels"`
	// Identifying fields for accurate merging
	SrcWorkloadHref string `json:"src_workload_href"`
	DstWorkloadHref string `json:"dst_workload_href"`
	ProcessName     string `json:"process_name"`
	DstFQDN         string `json:"dst_fqdn"`
}

type AsyncQueryRequest struct {
	QueryName         string         `json:"query_name"`
	Sources           IncludeExclude `json:"sources"`
	Destinations      IncludeExclude `json:"destinations"`
	Services          ServiceFilter  `json:"services"`
	PolicyDecisions   []string       `json:"policy_decisions"`
	BoundaryDecisions []string       `json:"boundary_decisions,omitempty"`
	StartDate         string         `json:"start_date"`
	EndDate           string         `json:"end_date"`
	MaxResults        int            `json:"max_results"`
}

type ServiceFilter struct {
	Include []interface{} `json:"include"` // Use []interface{} to ensure [] in JSON
	Exclude []interface{} `json:"exclude"`
}

type ServiceRef struct {
	Href string `json:"href"`
}

type PortProtoService struct {
	Port   int `json:"port,omitempty"`
	ToPort int `json:"to_port,omitempty"`
	Proto  int `json:"proto,omitempty"`
}

type IncludeExclude struct {
	Include [][]LabelRef `json:"include"`
	Exclude []LabelRef   `json:"exclude"`
}

type LabelRef struct {
	Label          *Href  `json:"label,omitempty"`
	LabelGroup     *Href  `json:"label_group,omitempty"`
	IPList         *Href  `json:"ip_list,omitempty"`
	UserGroup      *Href  `json:"user_group,omitempty"`
	VirtualService *Href  `json:"virtual_service,omitempty"`
	VirtualServer  *Href  `json:"virtual_server,omitempty"`
	IPAddress      string `json:"ip_address,omitempty"`
}

type Href struct {
	Href string `json:"href"`
}

type AsyncQueryStatus struct {
	Href   string `json:"href"`
	Status string `json:"status"`
}
