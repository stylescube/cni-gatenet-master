#!/bin/bash
start_time=`date +%s`

BINARY=$GOPATH/src/github.com/orkun1675/cni-gatenet/cni-plugin/bin/gatenet
SERVER_KEY="/home/orkun/.ssh/id_rsa.msft"
SERVER_USER="azureuser"
MASTER_SERVER="orkun-kubenet2.eastus.cloudapp.azure.com"
NODE_SERVER="10.240.0.6"

go build -o $BINARY || { echo 'Compile failed.'; exit 1; }
echo "Compiled to: $BINARY"
ssh -i $SERVER_KEY $SERVER_USER@$MASTER_SERVER "ssh $SERVER_USER@$NODE_SERVER '\
    sudo systemctl stop kubelet && \
    sudo rm -rf /var/log/gatenet.log && \
    sudo journalctl --vacuum-time=1second &> /dev/null && \
    echo \"Stoped kubelet and deleted logs\"'"
scp -i $SERVER_KEY -oProxyCommand="ssh -i $SERVER_KEY -W %h:%p $SERVER_USER@$MASTER_SERVER" $BINARY $SERVER_USER@$NODE_SERVER:/tmp
echo "Copied to: $MASTER_SERVER->$NODE_SERVER"
ssh -i $SERVER_KEY $SERVER_USER@$MASTER_SERVER "ssh $SERVER_USER@$NODE_SERVER '\
    sudo mv /tmp/gatenet /opt/cni/bin && \
    sudo systemctl start kubelet && \
    echo \"Started kubelet\"'"

end_time=`date +%s`
runtime=$((end_time-start_time))
echo "Total time: $runtime seconds"
