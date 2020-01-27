from.common import DEFAULT_TIMEOUT
from .common import create_project_and_ns
from .common import get_user_client
from .common import USER_TOKEN
from .common import random_test_name
from .common import get_project_client_for_token
from .common import get_schedulable_nodes
from .common import validate_workload
from .common import TEST_IMAGE
from .common import validate_ingress
from .test_rke_cluster_provisioning import evaluate_clustername
from .test_rke_cluster_provisioning import K8S_VERSION_UPGRADE
from .test_rke_cluster_provisioning import create_and_validate_custom_host
import pytest
import time

cluster_detail = {"project": None, "namespace": None}


def test_zdt_rancher():
    # set max maxUnavailable to 1

    # upgrade k8s version
    client = get_user_client()
    clusters = client.list_cluster(name=evaluate_clustername()).data
    assert len(clusters) == 1
    cluster = clusters[0]
    rke_config = cluster.rancherKubernetesEngineConfig
    rke_updated_config = rke_config.copy()
    rke_updated_config["kubernetesVersion"] = K8S_VERSION_UPGRADE
    cluster = client.update(cluster,
                            name=cluster.name,
                            rancherKubernetesEngineConfig=rke_updated_config)

    # verify at any time only 1 worker nodes upgrade
    cluster=client.reload(cluster)
    cluster_state = cluster.state
    start = time.time()
    maxUnavailable = False
    while cluster_state!= "active":
        if time.time() - start > DEFAULT_TIMEOUT:
            raise AssertionError(
                "Timed out waiting for state to get to active")
        cluster_nodes = client.list_node(clusterId=cluster.id).data
        worker_nodes = []
        for node in cluster_nodes:
            if node.worker:
                if node.state!="active" and not maxUnavailable:
                    # maxUnavailable window has reached
                    maxUnavailable = True
                elif node.state!="active" and maxUnavailable:
                    # maxUnavailable window has reached
                    assert False, "number of worker nodes " \
                                  "unavailable is > maxUnavailable window"

        time.sleep(.5)

    # verify ingress pointing to demoneset is never down


@pytest.fixture(scope='module', autouse="True")
def create_project_client(request):
    # deploy a cluster - 1 etcd, 1 control, 3 worker - test_rke_custom_host_2()
    node_roles = [["controlplane"], ["etcd"],
                  ["worker"], ["worker"], ["worker"]]
    cluster, aws_nodes = create_and_validate_custom_host(node_roles)
    cluster_detail["project"], cluster_detail["namespace"] = \
        create_project_and_ns(USER_TOKEN,
                              cluster,
                              random_test_name("test_zero_dt"))
    p_client = get_project_client_for_token(cluster_detail["project"], USER_TOKEN)
    # deploy a demonset and an ingress
    con = [{"name": "test1",
            "image": TEST_IMAGE}]
    workload = p_client.create_workload(name="wk-01",
                                        containers=con,
                                        namespaceId=ns.id,
                                        daemonSetConfig={})
    validate_workload(p_client, workload, "daemonSet", cluster_detail["namespace"].name,
                      len(get_schedulable_nodes(cluster)))
    host = "test1.com"
    path = "/name.html"
    rule = {"host": host,
            "paths": [{"workloadIds": [workload.id], "targetPort": "80"}]}
    p_client.create_ingress(name="test-01",
                            namespaceId=cluster_detail["namespace"].id,
                            rules=[rule])
    validate_ingress(p_client, namespace["cluster"],
                     [workload], host, path)
