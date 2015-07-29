package tykcommon

import (
	"encoding/base64"
	"github.com/lonelycode/osin"
	"gopkg.in/mgo.v2/bson"
)

type AuthProviderCode string
type SessionProviderCode string
type StorageEngineCode string
type TykEvent string            // A type so we can ENUM event types easily, e.g. EVENT_QuotaExceeded
type TykEventHandlerName string // A type for handler codes in API definitions

type EndpointMethodAction string
type TemplateMode string

const (
	NoAction EndpointMethodAction = "no_action"
	Reply    EndpointMethodAction = "reply"

	UseBlob TemplateMode = "blob"
	UseFile TemplateMode = "file"

	RequestXML  RequestInputType = "xml"
	RequestJSON RequestInputType = "json"
)

type EndpointMethodMeta struct {
	Action  EndpointMethodAction `bson:"action" json:"action"`
	Code    int                  `bson:"code" json:"code"`
	Data    string               `bson:"data" json:"data"`
	Headers map[string]string    `bson:"headers" json:"headers"`
}

type EndPointMeta struct {
	Path          string                        `bson:"path" json:"path"`
	MethodActions map[string]EndpointMethodMeta `bson:"method_actions" json:"method_actions"`
}

type RequestInputType string

type TemplateMeta struct {
	TemplateData struct {
		Input          RequestInputType `bson:"input_type" json:"input_type"`
		Mode           TemplateMode     `bson:"template_mode" json:"template_mode"`
		TemplateSource string           `bson:"template_source" json:"template_source"`
	} `bson:"template_data" json:"template_data"`
	Path   string `bson:"path" json:"path"`
	Method string `bson:"method" json:"method"`
}

type HeaderInjectionMeta struct {
	DeleteHeaders []string          `bson:"delete_headers" json:"delete_headers"`
	AddHeaders    map[string]string `bson:"add_headers" json:"add_headers"`
	Path          string            `bson:"path" json:"path"`
	Method        string            `bson:"method" json:"method"`
	ActOnResponse bool              `bson:"act_on" json:"act_on"`
}

type HardTimeoutMeta struct {
	Path    string `bson:"path" json:"path"`
	Method  string `bson:"method" json:"method"`
	TimeOut int    `bson:"timeout" json:"timeout"`
}

type CircuitBreakerMeta struct {
	Path                 string  `bson:"path" json:"path"`
	Method               string  `bson:"method" json:"method"`
	ThresholdPercent     float64 `bson:"threshold_percent" json:"threshold_percent"`
	Samples              int64   `bson:"samples" json:"samples"`
	ReturnToServiceAfter int     `bson:"return_to_service_after" json:"return_to_service_after"`
}

type URLRewriteMeta struct {
	Path         string `bson:"path" json:"path"`
	Method       string `bson:"method" json:"method"`
	MatchPattern string `bson:"match_pattern" json:"match_pattern"`
	RewriteTo    string `bson:"rewrite_to" json:"rewrite_to"`
}

type VirtualMeta struct {
	ResponseFunctionName string `bson:"response_function_name" json:"response_function_name"`
	FunctionSourceType   string `bson:"function_source_type" json:"function_source_type"`
	FunctionSourceURI    string `bson:"function_source_uri" json:"function_source_uri"`
	Path                 string `bson:"path" json:"path"`
	Method               string `bson:"method" json:"method"`
	UseSession           bool   `bson:"use_session" json:"use_session"`
}

type VersionInfo struct {
	Name    string `bson:"name" json:"name"`
	Expires string `bson:"expires" json:"expires"`
	Paths   struct {
		Ignored   []string `bson:"ignored" json:"ignored"`
		WhiteList []string `bson:"white_list" json:"white_list"`
		BlackList []string `bson:"black_list" json:"black_list"`
	} `bson:"paths" json:"paths"`
	UseExtendedPaths bool `bson:"use_extended_paths" json:"use_extended_paths"`
	ExtendedPaths    struct {
		Ignored                 []EndPointMeta        `bson:"ignored" json:"ignored"`
		WhiteList               []EndPointMeta        `bson:"white_list" json:"white_list"`
		BlackList               []EndPointMeta        `bson:"black_list" json:"black_list"`
		Cached                  []string              `bson:"cache" json:"cache"`
		Transform               []TemplateMeta        `bson:"transform" json:"transform"`
		TransformResponse       []TemplateMeta        `bson:"transform_response" json:"transform_response"`
		TransformHeader         []HeaderInjectionMeta `bson:"transform_headers" json:"transform_headers"`
		TransformResponseHeader []HeaderInjectionMeta `bson:"transform_response_headers" json:"transform_response_headers"`
		HardTimeouts            []HardTimeoutMeta     `bson:"hard_timeouts" json:"hard_timeouts"`
		CircuitBreaker          []CircuitBreakerMeta  `bson:"circuit_breakers" json:"circuit_breakers"`
		URLRewrite              []URLRewriteMeta      `bson:"url_rewrites" json:"url_rewrites"`
		Virtual                 []VirtualMeta         `bson:"virtual" json:"virtual"`
	} `bson:"extended_paths" json:"extended_paths"`
}

type AuthProviderMeta struct {
	Name          AuthProviderCode  `bson:"name" json:"name"`
	StorageEngine StorageEngineCode `bson:"storage_engine" json:"storage_engine"`
	Meta          interface{}       `bson:"meta" json:"meta"`
}

type SessionProviderMeta struct {
	Name          SessionProviderCode `bson:"name" json:"name"`
	StorageEngine StorageEngineCode   `bson:"storage_engine" json:"storage_engine"`
	Meta          interface{}         `bson:"meta" json:"meta"`
}

type EventHandlerTriggerConfig struct {
	Handler     TykEventHandlerName `bson:"handler_name" json:"handler_name"`
	HandlerMeta interface{}         `bson:"handler_meta" json:"handler_meta"`
}

type EventHandlerMetaConfig struct {
	Events map[TykEvent][]EventHandlerTriggerConfig `bson:"events" json:"events"`
}

type MiddlewareDefinition struct {
	Name           string `bson:"name" json:"name"`
	Path           string `bson:"path" json:"path"`
	RequireSession bool   `bson:"require_session" json:"require_session"`
}

type MiddlewareSection struct {
	Pre  []MiddlewareDefinition `bson:"pre" json:"pre"`
	Post []MiddlewareDefinition `bson:"post" json:"post"`
}

type CacheOptions struct {
	CacheTimeout               int64 `bson:"cache_timeout" json:"cache_timeout"`
	EnableCache                bool  `bson:"enable_cache" json:"enable_cache"`
	CacheAllSafeRequests       bool  `bson:"cache_all_safe_requests" json:"cache_all_safe_requests"`
	EnableUpstreamCacheControl bool  `bson:"enable_upstream_cache_control" json:"enable_upstream_cache_control"`
}

type ResponseProcessor struct {
	Name    string      `bson:"name" json:"name"`
	Options interface{} `bson:"options" json:"options"`
}

// APIDefinition represents the configuration for a single proxied API and it's versions.
type APIDefinition struct {
	Id               bson.ObjectId `bson:"_id,omitempty" json:"id,omitempty"`
	Name             string        `bson:"name" json:"name"`
	Slug             string        `bson:"slug" json:"slug"`
	APIID            string        `bson:"api_id" json:"api_id"`
	OrgID            string        `bson:"org_id" json:"org_id"`
	UseKeylessAccess bool          `bson:"use_keyless" json:"use_keyless"`
	UseOauth2        bool          `bson:"use_oauth2" json:"use_oauth2"`
	Oauth2Meta       struct {
		AllowedAccessTypes     []osin.AccessRequestType    `bson:"allowed_access_types" json:"allowed_access_types"`
		AllowedAuthorizeTypes  []osin.AuthorizeRequestType `bson:"allowed_authorize_types" json:"allowed_authorize_types"`
		AuthorizeLoginRedirect string                      `bson:"auth_login_redirect" json:"auth_login_redirect"`
	} `bson:"oauth_meta" json:"oauth_meta"`
	Auth struct {
		UseParam       bool   `mapstructure:"use_param" bson:"use_param" json:"use_param"`
		AuthHeaderName string `mapstructure:"auth_header_name" bson:"auth_header_name" json:"auth_header_name"`
	} `bson:"auth" json:"auth"`
	UseBasicAuth            bool                 `bson:"use_basic_auth" json:"use_basic_auth"`
	NotificationsDetails    NotificationsManager `bson:"notifications" json:"notifications"`
	EnableSignatureChecking bool                 `bson:"enable_signature_checking" json:"enable_signature_checking"`
	HmacAllowedClockSkew    float64              `bson:"hmac_allowed_clock_skew" json:"hmac_allowed_clock_skew"`
	VersionDefinition       struct {
		Location string `bson:"location" json:"location"`
		Key      string `bson:"key" json:"key"`
	} `bson:"definition" json:"definition"`
	VersionData struct {
		NotVersioned bool                   `bson:"not_versioned" json:"not_versioned"`
		Versions     map[string]VersionInfo `bson:"versions" json:"versions"`
	} `bson:"version_data" json:"version_data"`
	Proxy struct {
		ListenPath          string   `bson:"listen_path" json:"listen_path"`
		TargetURL           string   `bson:"target_url" json:"target_url"`
		StripListenPath     bool     `bson:"strip_listen_path" json:"strip_listen_path"`
		EnableLoadBalancing bool     `bson:"enable_load_balancing" json:"enable_load_balancing"`
		TargetList          []string `bson:"target_list" json:"target_list"`
		ServiceDiscovery    struct {
			UseDiscoveryService bool   `bson:"use_discovery_service" json:"use_discovery_service"`
			QueryEndpoint       string `bson:"query_endpoint" json:"query_endpoint"`
			UseNestedQuery      bool   `bson:"use_nested_query" json:"use_nested_query"`
			ParentDataPath      string `bson:"parent_data_path" json:"parent_data_path"`
			DataPath            string `bson:"data_path" json:"data_path"`
			PortDataPath        string `bson:"port_data_path" json:"port_data_path"`
			UseTargetList       bool   `bson:"use_target_list" json:"use_target_list"`
			CacheTimeout        int64  `bson:"cache_timeout" json:"cache_timeout"`
		} `bson:"service_discovery" json:"service_discovery"`
	} `bson:"proxy" json:"proxy"`
	CustomMiddleware          MiddlewareSection      `bson:"custom_middleware" json:"custom_middleware"`
	CacheOptions              CacheOptions           `bson:"cache_options" json:"cache_options"`
	SessionLifetime           int64                  `bson:"session_lifetime" json:"session_lifetime"`
	Active                    bool                   `bson:"active" json:"active"`
	AuthProvider              AuthProviderMeta       `bson:"auth_provider" json:"auth_provider"`
	SessionProvider           SessionProviderMeta    `bson:"session_provider" json:"session_provider"`
	EventHandlers             EventHandlerMetaConfig `bson:"event_handlers" json:"event_handlers"`
	EnableBatchRequestSupport bool                   `bson:"enable_batch_request_support" json:"enable_batch_request_support"`
	EnableIpWhiteListing      bool                   `mapstructure:"enable_ip_whitelisting" bson:"enable_ip_whitelisting" json:"enable_ip_whitelisting"`
	AllowedIPs                []string               `mapstructure:"allowed_ips" bson:"allowed_ips" json:"allowed_ips"`
	DontSetQuotasOnCreate     bool                   `mapstructure:"dont_set_quota_on_create" bson:"dont_set_quota_on_create" json:"dont_set_quota_on_create"`
	ExpireAnalyticsAfter      int64                  `mapstructure:"expire_analytics_after" bson:"expire_analytics_after" json:"expire_analytics_after"` // must have an expireAt TTL index set (http://docs.mongodb.org/manual/tutorial/expire-data/)
	ResponseProcessors        []ResponseProcessor    `bson:"response_processors" json:"response_processors"`
	RawData                   map[string]interface{} `bson:"raw_data,omitempty" json:"raw_data,omitempty"` // Not used in actual configuration, loaded by config for plugable arc
}

// Clean will URL encode map[string]struct variables for saving
func (a *APIDefinition) EncodeForDB() {
	new_version := make(map[string]VersionInfo)
	for k, v := range a.VersionData.Versions {
		newK := base64.StdEncoding.EncodeToString([]byte(k))
		v.Name = newK
		new_version[newK] = v

	}

	a.VersionData.Versions = new_version
	//	log.Warning(a.VersionData.Versions)
}

func (a *APIDefinition) DecodeFromDB() {
	new_version := make(map[string]VersionInfo)
	for k, v := range a.VersionData.Versions {
		newK, decErr := base64.StdEncoding.DecodeString(k)
		if decErr != nil {
			log.Error("Couldn't Decode, leaving as it may be legacy...")
			new_version[k] = v
		} else {
			v.Name = string(newK)
			new_version[string(newK)] = v
		}
	}

	a.VersionData.Versions = new_version
	//	log.Warning(a.VersionData.Versions)
}
