#!/bin/bash

cd ${0%*/*}

docker_pause=`/bin/ls /opt/mellanox/doca/services/infrastructure/docker_pause*.tar`
doca_telemetry=`/bin/ls doca_telemetry_service*arm64.tar`
doca_telemetry_yaml=`/bin/ls doca_telemetry*.yaml`

if [ ! -n $doca_telemetry ]; then
	echo "DOCA telemetry container image was not found"
	exit 1
fi

if [ ! -n $docker_pause ]; then
        echo "Docker Pause container image was not found"
        exit 1
fi

ex()
{
	eval "$@"
	rc=$?

	if [ $rc -ne 0 ]; then
		echo "ERROR: Failed executing $@ RC: $rc"
		exit $rc
	fi
}

ex systemctl enable kubelet.service
ex systemctl enable containerd.service

ex systemctl start kubelet.service
ex systemctl start containerd.service

ex ctr --namespace k8s.io image import $doca_telemetry
ex ctr --namespace k8s.io image import $docker_pause
ex cp $doca_telemetry_yaml /etc/kubelet.d/
