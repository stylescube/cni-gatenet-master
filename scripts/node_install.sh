#!/bin/bash

URL_GATENET_RELEASE=https://raw.githubusercontent.com/orkun1675/cni-gatenet/master/release
URL_CNI_RELEASE=https://github.com/containernetworking/cni/releases/download/v0.3.0/cni-v0.3.0.tgz

CNI_CONFIG_DIR=/etc/cni/net.d
CNI_BIN_DIR=/opt/cni/bin
KUBELET_OPTIONS=/etc/default/kubelet

createCleanFolder () {
    rm -rf ${1}
    mkdir -p ${1}
    chown -R root:root ${1}
    chmod 755 ${1}
}

setNetworkPlugin () {
    sed -i "s/^KUBELET_NETWORK_PLUGIN=.*/KUBELET_NETWORK_PLUGIN=${1}/" $KUBELET_OPTIONS
}

addUnsafeSysctl () {
    sed -i "s/^KUBELET_FEATURE_GATES=/ s/$/ ${1}/" $KUBELET_OPTIONS
    #This has to be added manully to "/etc/systemd/system/kubelet.service". We need to add acs-engine support instead.
}

setDockerOpts () {
    sed -i "s#^DOCKER_OPTS=.*#DOCKER_OPTS=${1}#" $KUBELET_OPTIONS
}

createCleanFolder $CNI_CONFIG_DIR
createCleanFolder $CNI_BIN_DIR
echo "Created folders."

wget $URL_GATENET_RELEASE/10-gatenet.conf -qP $CNI_CONFIG_DIR
chmod 600 $CNI_CONFIG_DIR/10-gatenet.conf
wget $URL_GATENET_RELEASE/gatenet -qP $CNI_BIN_DIR
chmod +x $CNI_BIN_DIR/gatenet
wget -qO- $URL_CNI_RELEASE | tar -xz -C $CNI_BIN_DIR ./loopback ./host-local ./ptp
echo "Fetched downlaods."

setNetworkPlugin cni
addUnsafeSysctl "--experimental-allowed-unsafe-sysctls=net.ipv4.conf.all.rp_filter,net.ipv4.conf.default.rp_filter"
setDockerOpts " --volume=/etc/cni/:/etc/cni:ro --volume=/opt/cni/:/opt/cni:ro"
echo "Set options."

modprobe ipip
modprobe fou
echo "Loaded neccesary kernel modules."

systemctl restart kubelet
echo "Done: kubelet restarted."