#!/bin/bash
start_time=`date +%s`

PROJECT=$GOPATH/src/github.com/orkun1675/cni-gatenet/gateway-image
BINARY=$PROJECT/bin/gate
DOCKERTAG="orkun1675/cni-gatenet:0.1"

go build -o $BINARY || { echo 'Compile failed.'; exit 1; }
echo "Compiled to: $BINARY"
docker build $PROJECT -t $DOCKERTAG || { echo 'Docker build failed.'; exit 1; }
docker push $DOCKERTAG || { echo 'Docker push failed.'; exit 1; }
echo "Docker image updated: $DOCKERTAG"

end_time=`date +%s`
runtime=$((end_time-start_time))
echo "Total time: $runtime seconds"
