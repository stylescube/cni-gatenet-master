package config

import (
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/vishvananda/netlink"
)

const (
	// MarkedTableID is used to mark outgoing packages and make sure they are sent using the correct routing table.
	MarkedTableID = 7
)

// GateNetConf defines the config structure for this plugin.
// The config file is usually found in /etc/cni/net.d
type GateNetConf struct {
	types.NetConf
	RawPrevResult     *map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult        *current.Result         `json:"-"`
	MainInterfaceName string                  `json:"mainInterfaceName"`
	Tunnel            *Tunnel                 `json:"tunnel"`
	GateIP            string                  `json:"gateIP"`
	Kubernetes        *Kubernetes             `json:"kubernetes"`
	LogLevel          string                  `json:"logLevel,omitempty"`
}

// Tunnel is used for configration
type Tunnel struct {
	Name      string     `json:"name"`
	Range     int        `json:"ipRange"`
	Port      int        `json:"port"`
	TTL       int        `json:"ttl"`
	Endpoints *Endpoints `json:"endpoints"`
}

// Endpoints is used for configration
type Endpoints struct {
	Local string `json:"local"`
	Gate  string `json:"gate"`
}

// Kubernetes is used for configration
type Kubernetes struct {
	KubeConfig        string   `json:"kubeConfig"`
	NodeName          string   `json:"nodeName,omitempty"`
	IgnoredNamespaces []string `json:"ignoredNamespaces"`
}

// CreateTunnelLink creates a new FOU tunnel over IPIP
func CreateTunnelLink(gateSide bool, conf *GateNetConf, localPodIP net.IP, remotePodIP net.IP, linkName string) (*netlink.Iptun, error) {
	tunnelLocalEndpoint := conf.Tunnel.Endpoints.Local
	if gateSide {
		tunnelLocalEndpoint = conf.Tunnel.Endpoints.Gate
	}

	tunLink := &netlink.Iptun{}
	tunLink.Ttl = uint8(conf.Tunnel.TTL)
	tunLink.PMtuDisc = 1 //Default value used by netlink examples.
	tunLink.Local = localPodIP
	tunLink.Remote = remotePodIP
	tunLink.EncapSport = uint16(conf.Tunnel.Port)
	tunLink.EncapDport = uint16(conf.Tunnel.Port)
	tunLink.EncapType = uint16(2)  //We should use enums instead. This is a temporary hack until netlink implements this.
	tunLink.EncapFlags = uint16(1) //We should use enums instead. This is a temporary hack until netlink implements this.
	tunLink.LinkAttrs = netlink.NewLinkAttrs()
	tunLink.LinkAttrs.Name = linkName

	if err := netlink.LinkAdd(tunLink); err != nil {
		return tunLink, fmt.Errorf("cannot create the tunnel: %v", err)
	}

	if err := netlink.LinkSetUp(tunLink); err != nil {
		return tunLink, fmt.Errorf("cannot set the tunnel up: %v", err)
	}

	tunAddress := &net.IPNet{IP: net.ParseIP(tunnelLocalEndpoint), Mask: net.CIDRMask(conf.Tunnel.Range, 32)}
	tunAddr := &netlink.Addr{IPNet: tunAddress}
	if err := netlink.AddrAdd(tunLink, tunAddr); err != nil {
		return tunLink, fmt.Errorf("cannot add IP to tunnel: %v", err)
	}

	return tunLink, nil
}
