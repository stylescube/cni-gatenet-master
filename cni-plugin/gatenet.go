package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"

	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	utildbus "k8s.io/kubernetes/pkg/util/dbus"
	utilexec "k8s.io/kubernetes/pkg/util/exec"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"

	. "github.com/orkun1675/cni-gatenet/config"
)

const (
	ptpNetConf = `{
	"name": "%s",
	"type": "ptp",
	"ipam": {
		"type": "host-local",
		"subnet": "%s",
		"gateway": "%s",
		"routes": [
			{ "dst": "0.0.0.0/0" }
		]
	}
}`
	k8sPodNameKey      = "K8S_POD_NAME="
	k8sPodNamespaceKey = "K8S_POD_NAMESPACE="
	k8sArgsSplitter    = ";"
)

var (
	nodeName    string
	log         = logrus.New()
	defaultConf = &GateNetConf{
		MainInterfaceName: "eth0",
		Tunnel: &Tunnel{
			Name:  "tun1",
			Range: 30,
			Port:  5454,
			TTL:   10,
			Endpoints: &Endpoints{
				Local: "10.0.0.2",
				Gate:  "10.0.0.1",
			},
		},
		GateIP: "10.0.10.10",
		Kubernetes: &Kubernetes{
			KubeConfig:        "/var/lib/kubelet/kubeconfig",
			NodeName:          "",
			IgnoredNamespaces: []string{"kube-system"},
		},
		LogLevel: "debug",
	}
)

func init() {
	runtime.LockOSThread()
	nodeStr, err := os.Hostname()
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Warn("could not get the hostname of this OS, if Kubernetes.NodeName is not set plugin will fail")
	}
	nodeName = nodeStr

	log.Formatter = new(logrus.TextFormatter)
	log.Level = logrus.DebugLevel
	file, err := os.OpenFile("/var/log/gatenet.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
	} else {
		log.Info("failed to log to file, using default stderr")
	}
}

func parseConfig(stdin []byte) (*GateNetConf, error) {
	conf := *defaultConf

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("could not parse the config: %v", err)
	}

	if res := net.ParseIP(conf.GateIP); res == nil {
		return nil, fmt.Errorf("config.gateIP is not a valid IP address: %s", conf.GateIP)
	}

	if len(conf.Tunnel.Name) > 15 || len(conf.Tunnel.Name) < 3 {
		return nil, fmt.Errorf("invalid tunnel name: %s", conf.Tunnel.Name)
	}

	if conf.Tunnel.Range > 31 || conf.Tunnel.Range < 0 {
		return nil, fmt.Errorf("invalid tunnel IP range: %s", conf.Tunnel.Name)
	}

	lvl, err := logrus.ParseLevel(conf.LogLevel)
	if err == nil {
		log.Level = lvl
	}

	return &conf, nil
}

func getPodCIDR(conf *GateNetConf) (string, error) {
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", conf.Kubernetes.KubeConfig)
	if err != nil {
		return "", fmt.Errorf("could not build Kubeconfig: %v", err)
	}

	clientSet, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return "", fmt.Errorf("could not create the k8s client set: %v", err)
	}

	nodeStr := nodeName
	if conf.Kubernetes.NodeName != "" {
		nodeStr = conf.Kubernetes.NodeName
	}

	node, err := clientSet.Nodes().Get(nodeStr, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("could not get node description for node %s: %v", nodeStr, err)
	}

	if node.Spec.PodCIDR == "" {
		return "", fmt.Errorf("node %s does not have podCidr set: %v", nodeStr, err)
	}
	return node.Spec.PodCIDR, nil
}

func getGateWayIP(podCIDR string) (string, error) {
	_, parsedPodCIDR, err := net.ParseCIDR(podCIDR)
	if err != nil {
		return "", fmt.Errorf("could not parse pod CIDR: %s", podCIDR)
	}
	parsedPodCIDR.IP[len(parsedPodCIDR.IP)-1]++
	return parsedPodCIDR.IP.String(), nil
}

func getPtpConf(conf *GateNetConf) (string, error) {
	podCIDR, err := getPodCIDR(conf)
	if err != nil {
		return "", err
	}
	log.WithFields(logrus.Fields{
		"podCIDR": podCIDR,
	}).Debug("got pod ip range from kubernetes")

	gatewayIP, err := getGateWayIP(podCIDR)
	if err != nil {
		return "", err
	}

	ptpConf := fmt.Sprintf(ptpNetConf, conf.MainInterfaceName, podCIDR, gatewayIP)
	log.WithFields(logrus.Fields{
		"json": ptpConf,
	}).Debug("PTP conf generated")

	return ptpConf, nil
}

func getPodDetails(args string) (string, string) {
	podName := ""
	podNs := ""

	argSlice := strings.Split(args, k8sArgsSplitter)
	for _, arg := range argSlice {
		if strings.HasPrefix(arg, k8sPodNameKey) {
			podName = strings.TrimPrefix(arg, k8sPodNameKey)
		} else if strings.HasPrefix(arg, k8sPodNamespaceKey) {
			podNs = strings.TrimPrefix(arg, k8sPodNamespaceKey)
		}
	}
	return podName, podNs
}

func createTunnel(netns ns.NetNS, conf *GateNetConf, ifaceIP net.IP) (*current.Interface, error) {
	tunIFace := &current.Interface{}

	err := netns.Do(func(hostNS ns.NetNS) error {
		log.WithFields(logrus.Fields{
			"hostNS": hostNS.Path(),
			"contNS": netns.Path(),
		}).Debug("switched to network space")

		/*
			These should be run by the host when provisoning, instead.
			They take to much execution time when instead the plugin and throw errors.

			if out, err := exec.Command("depmod").CombinedOutput(); err != nil {
				return fmt.Errorf("running command depmod returned: %v with error: %v", string(out), err)
			}
			if out, err := exec.Command("modprobe", "ipip").CombinedOutput(); err != nil {
				return fmt.Errorf("running command modprobe ipip returned: %v with error: %v", string(out), err)
			}
			if out, err := exec.Command("modprobe", "fou").CombinedOutput(); err != nil {
				return fmt.Errorf("running command modprobe fou returned: %v with error: %v", string(out), err)
			}
		*/

		ipFou := netlink.NewFou()
		ipFou.Port = conf.Tunnel.Port
		ipFou.Gue = true
		if err := netlink.FouAdd(ipFou); err != nil {
			return fmt.Errorf("error when adding fou gue at port %d: %v", conf.Tunnel.Port, err)
		}
		log.WithFields(logrus.Fields{
			"port": strconv.Itoa(int(ipFou.Port)),
		}).Debug("opened fou port for gue")

		tunLink, err := CreateTunnelLink(false, conf, ifaceIP, net.ParseIP(conf.GateIP), conf.Tunnel.Name)
		if err != nil {
			return err
		}

		tunIFace.Name = tunLink.Attrs().Name
		tunIFace.Mac = tunLink.Attrs().HardwareAddr.String()
		tunIFace.Sandbox = netns.Path()

		log.WithFields(logrus.Fields{
			"tunnelName": tunLink.LinkAttrs.Name,
		}).Debug("created tunnel and set address")

		return nil
	})

	return tunIFace, err
}

func ensureRouting(netns ns.NetNS, conf *GateNetConf) error {
	err := netns.Do(func(hostNS ns.NetNS) error {
		iptInterface := utiliptables.New(utilexec.New(), utildbus.New(), utiliptables.ProtocolIpv4)
		_, err := iptInterface.EnsureRule(utiliptables.Append, "mangle", utiliptables.ChainOutput,
			"-o", conf.MainInterfaceName, "-j", "MARK", "--set-mark", fmt.Sprintf("0x%d", MarkedTableID))
		if err != nil {
			return fmt.Errorf("could not modify iptables: %v", err)
		}

		ipRule := netlink.NewRule()
		ipRule.Table = MarkedTableID
		ipRule.Mark = MarkedTableID
		if err := netlink.RuleAdd(ipRule); err != nil {
			return fmt.Errorf("could not add ip rule: %v", err)
		}

		iface, _ := netlink.LinkByName(conf.Tunnel.Name)
		gate := net.ParseIP(conf.Tunnel.Endpoints.Gate)
		defaultRoute := netlink.Route{
			LinkIndex: iface.Attrs().Index,
			Dst:       nil,
			Gw:        gate,
			Table:     MarkedTableID,
		}
		if err := netlink.RouteReplace(&defaultRoute); err != nil {
			return fmt.Errorf("could not add default route: %v", err)
		}

		log.Debug("created iptables rule, ip rule, and route")

		return nil
	})
	return err
}

func cmdAdd(args *skel.CmdArgs) error {
	log.Debug("Add function called.")

	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}
	byteConf, _ := json.Marshal(conf)
	log.WithFields(logrus.Fields{
		"config": string(byteConf),
	}).Debug("config parsed")

	if conf.PrevResult != nil {
		return fmt.Errorf("must not be called as a chained plugin")
	}

	ptpConf, err := getPtpConf(conf)
	if err != nil {
		return err
	}

	oldRes, err := invoke.DelegateAdd("ptp", []byte(ptpConf))
	if err != nil {
		return fmt.Errorf("calling PTP.Add resulted in an error: %v", err)
	}
	res, err := current.NewResultFromResult(oldRes)
	if err != nil {
		return fmt.Errorf("could not parse the result of PTP.Add: %v", err)
	}
	if len(res.IPs) == 0 || res.IPs[0].Version != "4" {
		return fmt.Errorf("could not parse the result of PTP.Add: %s", res.String())
	}
	ifaceIP, _, err := net.ParseCIDR(res.IPs[0].Address.String())
	if err != nil {
		return fmt.Errorf("could not parse the result of PTP.Add: %v", err)
	}
	log.WithFields(logrus.Fields{
		"result":  res.String(),
		"ifaceIP": ifaceIP,
	}).Debug("PTP.Add was succesfull")

	specialPod := false
	podName, podNs := getPodDetails(args.Args)
	for _, ignoredNs := range conf.Kubernetes.IgnoredNamespaces {
		if strings.EqualFold(ignoredNs, podNs) {
			specialPod = true
			break
		}
	}

	if specialPod {
		log.WithFields(logrus.Fields{
			"podName": podName,
			"podNS":   podNs,
		}).Debug("pod is special, skipping tunnel setup")
	} else {
		log.WithFields(logrus.Fields{
			"podName": podName,
			"podNS":   podNs,
		}).Debug("pod is not special, requires tunnelling")

		netns, err := ns.GetNS(args.Netns)
		if err != nil {
			return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
		}
		defer netns.Close()

		log.WithFields(logrus.Fields{
			"path":      netns.Path(),
			"file desc": netns.Fd(),
		}).Debug("opened netns")

		tunnelInterface, err := createTunnel(netns, conf, ifaceIP)
		if err != nil {
			return fmt.Errorf("could not create tunnel: %v", err)
		}
		res.Interfaces = append(res.Interfaces, tunnelInterface)

		if err := ensureRouting(netns, conf); err != nil {
			return fmt.Errorf("%v", err)
		}
	}

	log.Debug("Add function complete.")
	return types.PrintResult(res, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	log.WithFields(logrus.Fields{
		"ifname": args.IfName,
	}).Debug("Del function called.")

	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}
	byteConf, _ := json.Marshal(conf)
	log.WithFields(logrus.Fields{
		"config": string(byteConf),
	}).Debug("config parsed")

	ptpConf, err := getPtpConf(conf)
	if err != nil {
		return err
	}

	err = invoke.DelegateDel("ptp", []byte(ptpConf))
	if err != nil {
		return fmt.Errorf("calling PTP.Del resulted in an error: %v", err)
	}
	log.Debug("PTP.Del was succesfull.")

	log.Debug("Del function complete.")
	return nil
}

func generate() {
	var filePath = "/etc/cni/net.d/999-gatenet.conf"

	js, err := json.MarshalIndent(defaultConf, "", "    ")
	if err != nil {
		fmt.Printf("could not marshal the default config: %v\n", err)
		return
	}
	err = ioutil.WriteFile(filePath, js, 0644)
	if err != nil {
		fmt.Printf("could not save the default config: %v\n", err)
		return
	}
	fmt.Printf("file save at: %s, don't forget to add `cniVersion` and `type`\n", filePath)
}

func main() {
	args := os.Args[1:]
	if len(args) >= 1 && strings.ToLower(args[0]) == "generate" {
		generate()
		return
	}

	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
