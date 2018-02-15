#!/bin/bash

ID=$(kubectl get nodes 2> /dev/null | grep -oP '(?<=k8s-master-)[0-9]+')

kubectl label node k8s-agentpool1-$ID-0 app=src --overwrite
kubectl label node k8s-agentpool1-$ID-1 app=dst --overwrite
kubectl label node k8s-agentpool1-$ID-2 app=gate --overwrite