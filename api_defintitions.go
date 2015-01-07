package tykcommon

import (
	"github.com/RangelReale/osin"
	"labix.org/v2/mgo/bson"
	"encoding/base64"
)

type AuthProviderCode string
type SessionProviderCode string
type StorageEngineCode string
type TykEvent string	// A type so we can ENUM event types easily, e.g. EVENT_QuotaExceeded
type TykEventHandlerName string // A type for handler codes in API definitions

type EndpointMethodAction string

const (
	NoAction EndpointMethodAction = "no_action"
	Reply EndpointMethodAction = "reply"
)

type EndpointMethodMeta struct {
	Action EndpointMethodAction	`bson:"action" json:"action"`
	Code int	`bson:"code" json:"code"`
	Data string	`bson:"data" json:"data"`
	Headers map[string]string `bson:"headers" json:"headers"`
}

type EndPointMeta struct {
	Path string `bson:"path" json:"path"`
	MethodActions map[string]EndpointMethodMeta `bson:"method_actions" json:"method_actions"`
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
	ExtendedPaths   struct {
		Ignored   []EndPointMeta `bson:"ignored" json:"ignored"`
		WhiteList []EndPointMeta `bson:"white_list" json:"white_list"`
		BlackList []EndPointMeta `bson:"black_list" json:"black_list"`
	} `bson:"extended_paths" json:"extended_paths"`
}

type AuthProviderMeta struct {
	Name AuthProviderCode	`bson:"name" json:"name"`
	StorageEngine StorageEngineCode `bson:"storage_engine" json:"storage_engine"`
	Meta interface{}		`bson:"meta" json:"meta"`
}

type SessionProviderMeta struct {
	Name SessionProviderCode	`bson:"name" json:"name"`
	StorageEngine StorageEngineCode `bson:"storage_engine" json:"storage_engine"`
	Meta interface{}			`bson:"meta" json:"meta"`
}

type EventHandlerTriggerConfig struct {
	Handler TykEventHandlerName	`bson:"handler_name" json:"handler_name"`
	HandlerMeta interface{} `bson:"handler_meta" json:"handler_meta"`
}

type EventHandlerMetaConfig struct {
	Events map[TykEvent][]EventHandlerTriggerConfig `bson:"events" json:"events"`
}

// APIDefinition represents the configuration for a single proxied API and it's versions.
type APIDefinition struct {
	Id               bson.ObjectId `bson:"_id,omitempty" json:"id"`
	Name             string        `bson:"name" json:"name"`
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
		AuthHeaderName string `mapstructure:"auth_header_name" bson:"auth_header_name" json:"auth_header_name"`
	} `bson:"auth" json:"auth"`
	UseBasicAuth            bool                 `bson:"use_basic_auth" json:"use_basic_auth"`
	NotificationsDetails    NotificationsManager `bson:"notifications" json:"notifications"`
	EnableSignatureChecking bool                 `bson:"enable_signature_checking" json:"enable_signature_checking"`
	VersionDefinition       struct {
		Location string `bson:"location" json:"location"`
		Key      string `bson:"key" json:"key"`
	} `bson:"definition" json:"definition"`
	VersionData struct {
		NotVersioned bool                   `bson:"not_versioned" json:"not_versioned"`
		Versions     map[string]VersionInfo `bson:"versions" json:"versions"`
	} `bson:"version_data" json:"version_data"`
	Proxy struct {
		ListenPath      string `bson:"listen_path" json:"listen_path"`
		TargetURL       string `bson:"target_url" json:"target_url"`
		StripListenPath bool   `bson:"strip_listen_path" json:"strip_listen_path"`
	} `bson:"proxy" json:"proxy"`
	SessionLifetime int64 `bson:"session_lifetime" json:"session_lifetime"`
	Active  bool                   `bson:"active" json:"active"`
	AuthProvider AuthProviderMeta	`bson:"auth_provider" json:"auth_provider"`
	SessionProvider SessionProviderMeta	`bson:"session_provider" json:"session_provider"`
	EventHandlers EventHandlerMetaConfig `bson:"event_handlers" json:"event_handlers"`
	EnableBatchRequestSupport bool	`bson:"enable_batch_request_support" json:"enable_batch_request_support"`
	EnableIpWhiteListing bool `mapstructure:"enable_ip_whitelisting" bson:"enable_ip_whitelisting" json:"enable_ip_whitelisting"`
	AllowedIPs []string `mapstructure:"allowed_ips" bson:"allowed_ips" json:"allowed_ips"`
	ExpireAnalyticsAfter int64 `mapstructure:"expire_analytics_after" bson:"expire_analytics_after" json:"expire_analytics_after"` // must have an expireAt TTL index set (http://docs.mongodb.org/manual/tutorial/expire-data/)
	RawData map[string]interface{} `bson:"raw_data,omitempty" json:"raw_data,omitempty"` // Not used in actual configuration, loaded by config for plugable arc
}

// Clean will URL encode map[string]struct variables for saving
func (a *APIDefinition) EncodeForDB() {
	new_version := make(map[string]VersionInfo)
	for k, v := range(a.VersionData.Versions) {
		newK := base64.StdEncoding.EncodeToString([]byte(k))
		v.Name = newK
		new_version[newK] = v

	}

	a.VersionData.Versions = new_version
//	log.Warning(a.VersionData.Versions)
}

func (a *APIDefinition) DecodeFromDB() {
	new_version := make(map[string]VersionInfo)
	for k, v := range(a.VersionData.Versions) {
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
