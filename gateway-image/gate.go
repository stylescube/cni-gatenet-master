package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/pkg/api/v1"
	//"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
	utildbus "k8s.io/kubernetes/pkg/util/dbus"
	utilexec "k8s.io/kubernetes/pkg/util/exec"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"

	"github.com/Sirupsen/logrus"

	. "github.com/orkun1675/cni-gatenet/config"
)

const (
	logFilePath          = "/root/gateway.log"
	cniConfigFilePath    = "/mnt/cni-conf/10-gatenet.conf"
	kubeConfigFilePath   = "/mnt/kube-conf/kubeconfig"
	tunnelLinkPrefix     = "tunG"
	retryPodSyncCount    = 3
	iptablesTableMangle  = "mangle"
	iptablesChainForward = "FORWARD"
)

var (
	log            = logrus.New()
	iptInterface   utiliptables.Interface
	localPodIP     net.IP
	tunneledPodIPs map[string]string
)

func init() {
	goruntime.LockOSThread()

	log.Formatter = new(logrus.TextFormatter)
	log.Level = logrus.DebugLevel
	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
		log.Info("initialized logger to log to file")
	} else {
		log.Info("failed to log to file, using default stderr")
	}

	iptInterface = utiliptables.New(utilexec.New(), utildbus.New(), utiliptables.ProtocolIpv4)
	localPodIP = nil
	tunneledPodIPs = make(map[string]string)
}

func parseConfig() (*GateNetConf, error) {
	conf := &GateNetConf{}

	rawFile, err := ioutil.ReadFile(cniConfigFilePath)
	if err != nil {
		return conf, fmt.Errorf("could not read config file: %v", err)
	}

	if err := json.Unmarshal(rawFile, conf); err != nil {
		return conf, fmt.Errorf("could not parse the config: %v", err)
	}

	return conf, nil
}

func listenGuePort(conf *GateNetConf) {
	out, err := exec.Command("ip", "-V").CombinedOutput()
	if err != nil {
		log.WithFields(logrus.Fields{
			"out":   string(out),
			"error": err.Error(),
		}).Fatal("failed to execute ip command")
	}
	log.WithFields(logrus.Fields{
		"version": strings.TrimSpace(string(out)),
	}).Debug("using ip command")

	if out, err := exec.Command("ip", "fou", "add", "port", strconv.Itoa(conf.Tunnel.Port), "gue").CombinedOutput(); err != nil {
		if strings.Contains(string(out), "Address already in use") {
			log.WithFields(logrus.Fields{
				"port": conf.Tunnel.Port,
			}).Debug("fou port already listening, skipping ip fou add command")
		} else {
			log.WithFields(logrus.Fields{
				"port":  conf.Tunnel.Port,
				"out":   string(out),
				"error": err.Error(),
			}).Fatal("failed to execute ip fou add")
		}
	} else {
		log.WithFields(logrus.Fields{
			"port": conf.Tunnel.Port,
		}).Debug("command ip fou add succeeded, listening on port")
	}
}

func getK8sClient() (*kubernetes.Clientset, error) {
	// Tell glog (used by client-go) to log into STDERR.
	// This should be fixed by client-go soon.
	flag.Set("logtostderr", "true")

	kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not build Kubeconfig: %v", err)
	}

	clientSet, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("could not create the k8s client set: %v", err)
	}

	return clientSet, nil
}

type controller struct {
	conf     *GateNetConf
	indexer  cache.Indexer
	queue    workqueue.RateLimitingInterface
	informer cache.Controller
}

func newController(conf *GateNetConf, queue workqueue.RateLimitingInterface, indexer cache.Indexer, informer cache.Controller) *controller {
	return &controller{
		conf:     conf,
		informer: informer,
		indexer:  indexer,
		queue:    queue,
	}
}

func (c *controller) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(key)
	err := c.syncPod(key.(string))
	c.handleErr(err, key)
	return true
}

func (c *controller) syncPod(key string) error {
	obj, exists, err := c.indexer.GetByKey(key)
	if err != nil {
		log.WithFields(logrus.Fields{
			"key":   key,
			"error": err.Error(),
		}).Debug("fetching pod object from store failed")
		return err
	}

	if !exists {
		log.WithFields(logrus.Fields{
			"key": key,
		}).Debug("pod does not exist, skipping")
		return nil
	}

	objIsNil := obj == nil
	log.WithFields(logrus.Fields{
		"key":      key,
		"exists":   exists,
		"objIsNil": objIsNil,
	}).Debug("got pod object from store")

	handlePodUpdate(c.conf, obj.(*corev1.Pod))
	return nil
}

func (c *controller) handleErr(err error, key interface{}) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	if c.queue.NumRequeues(key) < retryPodSyncCount {
		log.WithFields(logrus.Fields{
			"key":        key,
			"error":      err.Error(),
			"retry left": retryPodSyncCount - c.queue.NumRequeues(key),
		}).Warn("could not sync pod, will retry")
		c.queue.AddRateLimited(key)
		return
	}

	c.queue.Forget(key)
	runtime.HandleError(err)
	log.WithFields(logrus.Fields{
		"key":         key,
		"error":       err.Error(),
		"tried count": retryPodSyncCount,
	}).Warn("could not sync pod, dropping it of the queue")
}

func (c *controller) Run(stopCh chan struct{}) {
	defer runtime.HandleCrash()

	defer c.queue.ShutDown()
	log.Debug("Starting Pod controller")

	go c.informer.Run(stopCh)

	if !cache.WaitForCacheSync(stopCh, c.informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("Timed out waiting for caches to sync"))
		return
	}

	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
	log.Debug("Stopping Pod controller")
}

func (c *controller) runWorker() {
	for c.processNextItem() {
	}
}

func watchPods(conf *GateNetConf, client *kubernetes.Clientset) {
	podListWatcher := cache.NewListWatchFromClient(client.CoreV1().RESTClient(), "pods", corev1.NamespaceDefault, fields.Everything())
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	indexer, informer := cache.NewIndexerInformer(podListWatcher, &corev1.Pod{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if key, err := cache.MetaNamespaceKeyFunc(obj); err == nil {
				queue.Add(key)
			}
		},
		UpdateFunc: func(old interface{}, new interface{}) {
			newPod := new.(*corev1.Pod)
			oldPod := old.(*corev1.Pod)
			if newPod.Status.PodIP == oldPod.Status.PodIP {
				return
			}
			if key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(old); err == nil {
				queue.Add(key)
			}
			if key, err := cache.MetaNamespaceKeyFunc(new); err == nil {
				queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			if key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj); err == nil {
				queue.Add(key)
			}
		},
	}, cache.Indexers{})

	controller := newController(conf, queue, indexer, informer)

	var wg sync.WaitGroup
	wg.Add(1)
	stop := make(chan struct{})
	defer close(stop)
	go controller.Run(stop)
	wg.Wait()
}

func getLocalPodIP(conf *GateNetConf) net.IP {
	if localPodIP != nil {
		return localPodIP
	}

	defLink, err := netlink.LinkByName(conf.MainInterfaceName)
	if err != nil {
		panic(fmt.Errorf("could not get the default interface %s: %v", conf.MainInterfaceName, err))
	}

	addrs, err := netlink.AddrList(defLink, netlink.FAMILY_V4)
	if err != nil || len(addrs) < 1 {
		panic(fmt.Errorf("could not get addr of default link %s: %v", defLink.Attrs().Name, err))
	}

	localPodIP := addrs[0].IPNet.IP
	return localPodIP
}

func setupTunnel(conf *GateNetConf, ip string) error {
	podIP := net.ParseIP(ip)
	if podIP == nil {
		return fmt.Errorf("could not parse pod IP %s", ip)
	}

	tunName := mapIPtoLinkName(podIP)
	if _, err := netlink.LinkByName(tunName); err == nil {
		log.WithFields(logrus.Fields{
			"tunnelName": tunName,
			"remoteIP":   ip,
		}).Debug("tunnel already exists")
		return nil
	}

	tunLink, err := CreateTunnelLink(true, conf, getLocalPodIP(conf), podIP, tunName)
	if err != nil {
		return err
	}

	ipAsInt := int(mapIPtoUint(podIP))
	ipAsHexStr := mapIPtoMark(podIP)

	ipRule := netlink.NewRule()
	ipRule.Table = ipAsInt
	ipRule.Mark = ipAsInt
	if err := netlink.RuleAdd(ipRule); err != nil {
		return fmt.Errorf("could not add ip rule: %v", err)
	}

	tunPodEndpoint := net.ParseIP(conf.Tunnel.Endpoints.Local)
	defaultRoute := netlink.Route{
		LinkIndex: tunLink.Attrs().Index,
		Dst:       nil,
		Gw:        tunPodEndpoint,
		Table:     ipAsInt,
	}
	if err := netlink.RouteReplace(&defaultRoute); err != nil {
		return fmt.Errorf("could not add default route: %v", err)
	}

	_, err = iptInterface.EnsureRule(utiliptables.Append, iptablesTableMangle, iptablesChainForward,
		"-s", ip, "-j", "CONNMARK", "--set-mark", ipAsHexStr)
	if err != nil {
		return fmt.Errorf("could not ensure iptables set CONNMARK rule: %v", err)
	}

	_, err = iptInterface.EnsureRule(utiliptables.Append, iptablesTableMangle, utiliptables.ChainPrerouting,
		"-j", "CONNMARK", "--restore-mark")
	if err != nil {
		return fmt.Errorf("could not ensure iptables restore CONNMARK rule: %v", err)
	}

	_, err = iptInterface.EnsureRule(utiliptables.Append, utiliptables.TableNAT, utiliptables.ChainPostrouting,
		"-o", conf.MainInterfaceName, "-j", "MASQUERADE")
	if err != nil {
		return fmt.Errorf("could not ensure iptables MASQUERADE rule: %v", err)
	}

	return nil
}

func removeTunnel(conf *GateNetConf, ip string) error {
	podIP := net.ParseIP(ip)
	if podIP == nil {
		return fmt.Errorf("could not parse pod IP %s", ip)
	}

	tunName := mapIPtoLinkName(podIP)
	tunLink, err := netlink.LinkByName(tunName)
	if err != nil {
		return fmt.Errorf("pod IP %s does not have tunnel with name %s", ip, tunName)
	}

	ipAsInt := int(mapIPtoUint(podIP))
	ipAsHexStr := mapIPtoMark(podIP)

	ipRule := netlink.NewRule()
	ipRule.Table = ipAsInt
	ipRule.Mark = ipAsInt
	if err := netlink.RuleDel(ipRule); err != nil {
		return fmt.Errorf("could not delete ip rule: %v", err)
	}

	tunPodEndpoint := net.ParseIP(conf.Tunnel.Endpoints.Local)
	defaultRoute := netlink.Route{
		LinkIndex: tunLink.Attrs().Index,
		Dst:       nil,
		Gw:        tunPodEndpoint,
		Table:     ipAsInt,
	}
	if err := netlink.RouteDel(&defaultRoute); err != nil {
		return fmt.Errorf("could not delete default route: %v", err)
	}

	if err := netlink.LinkDel(tunLink); err != nil {
		return fmt.Errorf("pod IP %s tunnel %s could not be deleted", ip, tunName)
	}

	err = iptInterface.DeleteRule(iptablesTableMangle, iptablesChainForward,
		"-s", ip, "-j", "CONNMARK", "--set-mark", ipAsHexStr)
	if err != nil {
		return fmt.Errorf("could not delete iptables set CONNMARK rule: %v", err)
	}

	return nil
}

func cleanupTunnels() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("could not list links: %v", err)
	}

	counter := 0
	for _, link := range links {
		if strings.HasPrefix(link.Attrs().Name, tunnelLinkPrefix) {
			tunLink, ok := link.(*netlink.Iptun)
			if !ok {
				log.WithFields(logrus.Fields{
					"linkName": link.Attrs().Name,
					"error":    err.Error(),
				}).Warn("link with special prefix cant be cast to IPtun during cleanup")
			}

			podIP := tunLink.Remote
			ipAsInt := int(mapIPtoUint(podIP))

			ipRule := netlink.NewRule()
			ipRule.Table = ipAsInt
			ipRule.Mark = ipAsInt
			if err := netlink.RuleDel(ipRule); err != nil {
				log.WithFields(logrus.Fields{
					"linkName": link.Attrs().Name,
					"error":    err.Error(),
				}).Warn("could not delete ip rule during cleanup: %v")
			}

			defaultRoute := netlink.Route{
				LinkIndex: tunLink.Attrs().Index,
				Dst:       nil,
				Gw:        nil,
				Table:     ipAsInt,
			}
			if err := netlink.RouteDel(&defaultRoute); err != nil {
				log.WithFields(logrus.Fields{
					"linkName": link.Attrs().Name,
					"error":    err.Error(),
				}).Warn("could not delete default route during cleanup: %v")
			}

			if err = netlink.LinkDel(link); err != nil {
				log.WithFields(logrus.Fields{
					"linkName": link.Attrs().Name,
					"error":    err.Error(),
				}).Warn("could not delete link during cleanup")
			}
			counter++
		}
	}

	err = iptInterface.FlushChain(iptablesTableMangle, iptablesChainForward)
	if err != nil {
		return fmt.Errorf("could not flush iptables set CONNMARK rules: %v", err)
	}

	err = iptInterface.FlushChain(iptablesTableMangle, utiliptables.ChainPrerouting)
	if err != nil {
		return fmt.Errorf("could not flush restore CONNMARK rule: %v", err)
	}

	err = iptInterface.FlushChain(utiliptables.TableNAT, utiliptables.ChainPostrouting)
	if err != nil {
		return fmt.Errorf("could not flush iptables MASQUERADE rule: %v", err)
	}

	log.WithFields(logrus.Fields{
		"count": counter,
	}).Debug("cleaned up existing tunnels & iptables rules")

	return nil
}

func handlePodUpdate(conf *GateNetConf, pod *corev1.Pod) {
	log.WithFields(logrus.Fields{
		"name": pod.GetName(),
		"ns":   pod.GetNamespace(),
		"ip":   pod.Status.PodIP,
	}).Debug("pod update called")

	specialPod := false
	for _, ignoredNs := range conf.Kubernetes.IgnoredNamespaces {
		if strings.EqualFold(ignoredNs, pod.GetNamespace()) {
			specialPod = true
			break
		}
	}

	if specialPod {
		log.WithFields(logrus.Fields{
			"podName": pod.GetName(),
			"podNS":   pod.GetNamespace(),
		}).Debug("pod is special, skipping tunnel setup")
		return
	}

	log.WithFields(logrus.Fields{
		"podName": pod.GetName(),
		"podNS":   pod.GetNamespace(),
	}).Debug("pod is not special, requires tunnelling")

	var err error
	podKey := getKeyForPod(pod.GetName(), pod.GetNamespace())
	if len(pod.Status.PodIP) > 0 {
		err = setupTunnel(conf, pod.Status.PodIP)
		if err == nil {
			tunneledPodIPs[podKey] = pod.Status.PodIP
		}
	} else {
		if len(tunneledPodIPs[podKey]) > 0 {
			err = removeTunnel(conf, tunneledPodIPs[podKey])
		} else {
			log.WithFields(logrus.Fields{
				"podKey": podKey,
			}).Warn("tunnel for pod cant be deleted as it doesnt exist in ip map")
		}
	}
	if err != nil {
		log.WithFields(logrus.Fields{
			"name":  pod.GetName(),
			"ns":    pod.GetNamespace(),
			"ip":    pod.Status.PodIP,
			"error": err.Error(),
		}).Warn("pod update could not be handled")
	}
}

func main() {
	doCleanup()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		doCleanup()
		fmt.Println("exiting gate")
		os.Exit(0)
	}()

	conf, err := parseConfig()
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Fatal("could not fetch the cni config")
	}

	listenGuePort(conf)

	k8sClient, err := getK8sClient()
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Fatal("could not build k8s client")
	}
	log.Debug("built kubernetes client")

	watchPods(conf, k8sClient)
}

func doCleanup() {
	//return
	if err := cleanupTunnels(); err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Fatal("tunnel cleanup failed")
	}
}

func mapIPtoUint(ip net.IP) uint32 {
	ipB4 := ip.To4()
	return binary.BigEndian.Uint32(ipB4)
}

func mapIPtoStr(ip net.IP) string {
	num32 := mapIPtoUint(ip)
	hex8 := fmt.Sprintf("%08x", num32)
	return hex8
}

func mapIPtoLinkName(ip net.IP) string {
	return tunnelLinkPrefix + mapIPtoStr(ip)
}

func mapIPtoMark(ip net.IP) string {
	return "0x" + mapIPtoStr(ip)
}

func getKeyForPod(name, ns string) string {
	return ns + "/" + name
}
