package transport

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

func ProfileNames() []string {
	names := slices.Sorted(maps.Keys(profiles.MappedTLSClients))
	return append([]string{"default"}, names...)
}

func profileID(name string) (utls.ClientHelloID, error) {
	if strings.EqualFold(name, "default") || name == "" {
		return profiles.DefaultClientProfile.GetClientHelloId(), nil
	}
	profile, ok := profiles.MappedTLSClients[name]
	if !ok {
		return utls.ClientHelloID{}, fmt.Errorf("unrecognized TLS profile %q", name)
	}
	return profile.GetClientHelloId(), nil
}
