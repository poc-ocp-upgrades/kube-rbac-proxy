package authn

import (
	"errors"
	"time"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	authenticationclient "k8s.io/client-go/kubernetes/typed/authentication/v1beta1"
)

func NewDelegatingAuthenticator(client authenticationclient.TokenReviewInterface, authn *AuthnConfig) (authenticator.Request, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if client == nil {
		return nil, errors.New("tokenAccessReview client not provided, cannot use webhook authentication")
	}
	authenticatorConfig := authenticatorfactory.DelegatingAuthenticatorConfig{Anonymous: false, CacheTTL: 2 * time.Minute, ClientCAFile: authn.X509.ClientCAFile, TokenAccessReviewClient: client}
	authenticator, _, err := authenticatorConfig.New()
	return authenticator, err
}
