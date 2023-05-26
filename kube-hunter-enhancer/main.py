import re
import os
import time
import json
import html
from lxml import html
import requests
from bs4 import BeautifulSoup
import urllib.request as urllib2
import json
import subprocess
from tqdm import tqdm, trange

json_bin_link = input("Enter your npoint.io JSON bin link: ")

cmd = "kubectl get nodes -o wide"
result = subprocess.run(cmd, stdout=subprocess.PIPE, shell=True)


nodefile= result.stdout.decode("utf-8")

node_names = re.findall(r'^([\w-]+)\s+Ready\s+', nodefile, re.MULTILINE)

# print("List of nodes found in the cluster: ",node_names)

template = """
apiVersion: batch/v1
kind: Job
metadata:
  name: kube-hunter-<APP_NAME>
spec:
  template:
    metadata:
      labels:
        app: kube-hunter
    spec:
      nodeSelector:
        kubernetes.io/hostname: <NODE_NAME>
      containers:
        - name: kube-hunter
          image: 'aquasec/kube-hunter:0.6.8'
          command:
            - kube-hunter
          args:
            - '--pod'
      restartPolicy: Never
"""

if not os.path.exists('yaml'):
    os.makedirs('yaml')

for i, node_name in enumerate(node_names):
    app_name = str(i + 1)
    yaml_data = template.replace('<NODE_NAME>', node_name).replace('<APP_NAME>', app_name)
    filename = f'yaml/{node_name}.yaml'
    with open(filename, 'w') as f:
        f.write(yaml_data)
    os.system(f'kubectl apply -f {filename}')

# print(f'{len(node_names)} YAML files generated and deployed.')


logs_file = 'kube-hunter-logs.txt'

# Wait for pods to enter Running state
running_pods = set()

for node_name in node_names:
    pods = os.popen(f'kubectl get pods -l app=kube-hunter -o name').read().split()
    while len(running_pods) < len(node_names):
        time.sleep(3)
        for pod in pods:
            pod_name = pod.split('/')[-1]
            if pod_name not in running_pods:
                status = os.popen(f'kubectl get pod {pod_name} -o jsonpath="{{.status.phase}}"').read().strip()
                if status =='Succeeded':
                    # if status == 'Running' or 'Completed':
                    running_pods.add(pod_name)
    break
                    # print(f'Pod {pod_name} is now {status}.')

with open(logs_file, 'w') as f:
    for node_name in node_names:
        pods = os.popen(f'kubectl get pods -l app=kube-hunter -o name').read().split()
        for pod in pods:
            # print(pod)
            pod_name = pod.split('/')[-1]
            f.write(f'Logs for {pod_name} on node {node_name}:\n')
            f.write(os.popen(f'kubectl logs {pod_name}').read())
            f.write('\n\n')
        break

# print(f'Logs successfully written to {logs_file}.')

# read file

def solutions(idn):
    main_dict = {
    "khv002":"The vulnerability (khv002) is related to the fact that your Kubernetes cluster's version is publicly available, making it easier for attackers to exploit known vulnerabilities. To fix this issue, you need to disable the --enable-debugging-handlers flag in kubelet.\nTo do this, follow these steps:\nSSH into the node where kubelet is running\nOpen the kubelet configuration file located at /etc/kubernetes/kubelet.conf\nAdd --enable-debugging-handlers=false to the KUBELET_ARGS variable\nSave and close the file\nRestart the kubelet process using the command sudo systemctl restart kubelet\nBy following these steps, you will successfully disable the --enable-debugging-handlers flag in kubelet, which will prevent attackers from exploiting known vulnerabilities in your Kubernetes cluster's specific version",
    "khv003":"Check if your AKS cluster is running on or after the 2020.10.15 Azure VHD Release. You can check this by running the following command:\n\naz aks show --resource-group <resource-group-name> --name <cluster-name> --query agentPoolProfiles[0].imageVersion\n\nThis will return the image version of the agent pool used in the cluster.\n\nIf the image version is on or after 2020.10.15, then the pod CIDR access to the internal HTTP endpoint is already restricted by default and no further action is needed.\n\nIf the image version is before 2020.10.15, then you need to update your AKS cluster to at least that version. You can do this by running the following commands:\n\naz aks upgrade \\\n    --resource-group <resource-group-name> \\\n    --name <cluster-name> \\\n    --kubernetes-version <version>\nReplace <version> with a version equal to or greater than 1.18.14.\n\nOnce the AKS cluster is updated, pod CIDR access to the internal HTTP endpoint is automatically restricted.\n\nBy following these steps, you will mitigate vulnerability khv003 by restricting pod CIDR access to the internal HTTP endpoint in an AKS cluster.",
    "khv004":"Steps you can follow to fix vulnerability khv004:\n\nUpdate or rotate the cluster SPN (Service Principal Name) credentials frequently to avoid leaked credentials persisting over time. Refer to https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/aks/update-credentials.md for more details.\n\nConsider using Azure Managed Identities instead of a static SPN. However, this functionality is not yet mature and is currently available in alpha stage only for aks-engine (non-managed Kubernetes). Refer to https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview for more details.\n\nIf you are relying on a shared file on the node that contains credentials to the Azure API under /etc/kubernetes/azure.json, you need to ensure that access to this file is protected by appropriate file permissions so that unauthorized pod cannot read this file.\n\nBy following these steps, you will mitigate vulnerability khv004 by updating or rotating the cluster SPN credentials and protecting the shared file containing those credentials.",
    "khv005":"Steps you can follow to fix vulnerability khv005:\n\nExplicitly specify a Service Account for all of your workloads by setting the serviceAccountName field in Pod.Spec. This ensures that each workload has its own Service Account, which can be managed independently and with the least privilege principle in mind. Refer to https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/ for more details.\n\nConsider opting out automatic mounting of the Service Account token using automountServiceAccountToken: false on ServiceAccount resource or Pod.spec. By default, Kubernetes automatically mounts Service Account tokens into pods, but if the tokens are not needed, it is better to disable this feature to reduce the attack surface. Refer to https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#disable-automatic-mounting-of-the-serviceaccount-token for more details.\n\nReview the RBAC (Role-Based Access Control) permissions for the Service Accounts used by your workloads, and ensure that they have only the necessary permissions required to perform their tasks. You can do this by running the following command:\n\nkubectl get pod <pod-name> -o jsonpath='{.spec.serviceAccountName}'\nReplace <pod-name> with the name of the pod whose Service Account you want to check.\n\nBy following these steps, you will mitigate vulnerability khv005 by securing access to your Kubernetes API through the use of Service Accounts and RBAC permissions, and reducing the attack surface by disabling automatic mounting of Service Account tokens when they are not needed.",
    "khv006":"Steps you can follow to fix vulnerability khv006:\n\nEnsure your setup is exposing kube-api only on an HTTPS port. This can be done by setting the --tls-cert-file and --tls-private-key-file flags when starting the kube-apiserver process. Refer to https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/ for more details.\n\nDo not enable kube-api's --insecure-port flag in production. This flag allows the API server to listen on an insecure port (HTTP) in addition to the secure port (HTTPS). It should be used only for testing purposes during development, as it poses a significant security risk in production. If it is enabled, make sure that it is disabled immediately.\n\nBy following these steps, you will mitigate vulnerability khv006 by ensuring that your setup exposes kube-api only on an HTTPS port and disabling the use of the --insecure-port flag.",
    "khv007":"Steps you can follow to fix vulnerability khv007:\n\nReview the RBAC (Role-Based Access Control) permissions for the anonymous and default Service Accounts used by your workloads. The anonymous Service Account is used when no Service Account is explicitly specified in a Pod's serviceAccountName field, while the default Service Account is created automatically when a namespace is created. Both of these Service Accounts have access to the Kubernetes API server by default, so it is important to review their permissions and ensure that they only have the necessary permissions required to perform their tasks.\n\nUse the kubectl auth can-i command to test the permissions of the anonymous and default Service Accounts. For example, to test whether the anonymous Service Account has permission to create pods, run the following command:\n\nkubectl auth can-i create pods --as system:anonymous\nIf the command returns yes, then the anonymous Service Account has permission to create pods, which may be too permissive for your security requirements.\n\nConsider creating custom Service Accounts with limited RBAC permissions tailored to the specific needs of your workloads, and use them instead of the anonymous or default Service Accounts. This allows you to manage their permissions according to the least privilege principle and reduce the attack surface.\n\nBy following these steps, you will mitigate vulnerability khv007 by reviewing and managing the RBAC permissions for the anonymous and default Service Accounts used by your workloads, and creating custom Service Accounts with limited permissions tailored to the specific needs of your workloads.",
    "khv020":"Sure, here are the steps you can follow to fix vulnerability khv020:\n\nReview the securityContext of your pods and check whether the NET_RAW capability is enabled. This capability allows low-level network access to pods and can be abused to perform ARP spoofing attacks.\n\nConsider dropping the NET_RAW capability from your pods using Pod.spec.securityContext.capabilities. This removes the ability for pods to perform low-level network interactions that could be used for malicious purposes. To drop the NET_RAW capability, add the following lines to your pod specification:\n\nspec:\n  securityContext:\n    capabilities:\n      drop:\n      - NET_RAW\nIf you still require this capability for specific use cases, consider setting up an additional layer of protection such as network policies or a service mesh to restrict access and mitigate potential risks.\n\nBy following these steps, you will mitigate vulnerability khv020 by dropping the NET_RAW capability from your pods and removing the ability for them to perform low-level network interactions that could be used for ARP spoofing attacks.",
    "khv021":"Sure, here are the specific steps and commands you can follow to fix vulnerability khv021:\n\nGenerate a new TLS certificate for the Kubernetes API server using OpenSSL or another tool:\nopenssl req -newkey rsa:2048 -nodes -keyout <your-key-file>.key -out <your-cert-file>.csr -subj \"/CN=<your-kubernetes-hostname>\"\nopenssl x509 -req -in <your-cert-file>.csr -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key -CAcreateserial -out <your-cert-file>.crt -days 365\nEdit the Kubernetes API server configuration file (/etc/kubernetes/manifests/kube-apiserver.yaml) to reference the new TLS certificate:\nspec:\n  containers:\n  - command:\n    - kube-apiserver\n    - --tls-cert-file=/path/to/your-cert-file.crt\n    - --tls-private-key-file=/path/to/your-key-file.key\nRestart the Kubernetes API server to apply the changes:\nsystemctl restart kubelet.service\nBy following these steps, you will mitigate vulnerability khv021 by generating a new TLS certificate for the Kubernetes API server that does not include an email address and updating the Kubernetes API server configuration to reference the new certificate. You should then restart the Kubernetes API server to apply the changes.",
    "khv022":"Sure, here are the steps and commands you can follow to fix vulnerability khv022:\n\nUpgrade your Kubernetes control plane components (kube-apiserver, kube-controller-manager, kube-scheduler) to a version that includes the patch for CVE-2018-1002105. The fix was released in Kubernetes versions 1.10.11, 1.11.5, 1.12.3, and later. You should upgrade to the latest stable version of Kubernetes that is compatible with your environment.\n\nApply any additional patches or configuration changes necessary to fully mitigate the vulnerability. These may depend on the specifics of your cluster setup and the operating system it is running on.\n\nReview your RBAC policies to ensure that they are properly configured and do not allow unauthorized access to critical resources.\n\nBy following these steps, you will mitigate vulnerability khv022 by upgrading your Kubernetes control plane components to a version that includes the security patch for CVE-2018-1002105, applying any additional patches or configuration changes necessary to fully mitigate the vulnerability, and reviewing your RBAC policies to ensure that they are properly configured and do not allow unauthorized access.",
    "khv023":"Sure, here are the steps and commands you can follow to fix vulnerability khv023:\n\nUpgrade your Kubernetes API server to a version that includes the patch for CVE-2019-1002100. The fix was released in Kubernetes versions 1.13.5, 1.12.7, 1.11.9, and later. You should upgrade to the latest stable version of Kubernetes that is compatible with your environment.\n\nApply any additional patches or configuration changes necessary to fully mitigate the vulnerability. These may depend on the specifics of your cluster setup and the operating system it is running on.\n\nReview your network security policies to ensure that they are properly configured and do not allow unauthorized access to your Kubernetes API server.\n\nBy following these steps, you will mitigate vulnerability khv023 by upgrading your Kubernetes API server to a version that includes the security patch for CVE-2019-1002100, applying any additional patches or configuration changes necessary to fully mitigate the vulnerability, and reviewing your network security policies to ensure that they are properly configured and do not allow unauthorized access to your Kubernetes API server.",
    "khv024":"Sure, here are the steps and commands you can follow to fix vulnerability khv024:\n\nUpgrade your Kubernetes ingress-nginx controller to a version that includes the patch for CVE-2019-9512. The fix was released in ingress-nginx versions 0.24.1, 0.23.1, 0.22.1, and later. You should upgrade to the latest stable version of ingress-nginx that is compatible with your environment.\n\nApply any additional patches or configuration changes necessary to fully mitigate the vulnerability. These may depend on the specifics of your cluster setup and the operating system it is running on.\n\nReview your network security policies to ensure that they are properly configured and do not allow unauthorized access to your Kubernetes ingress-nginx controller.\n\nBy following these steps, you will mitigate vulnerability khv024 by upgrading your Kubernetes ingress-nginx controller to a version that includes the security patch for CVE-2019-9512, applying any additional patches or configuration changes necessary to fully mitigate the vulnerability, and reviewing your network security policies to ensure that they are properly configured and do not allow unauthorized access to your Kubernetes ingress-nginx controller.",
    "khv025":"Sure, here are the steps and commands you can follow to fix vulnerability khv025:\n\nUpgrade your Kubernetes ingress-nginx controller to a version that includes the patch for CVE-2019-9514. The fix was released in ingress-nginx versions 0.24.1, 0.23.1, 0.22.1, and later. You should upgrade to the latest stable version of ingress-nginx that is compatible with your environment.\n\nApply any additional patches or configuration changes necessary to fully mitigate the vulnerability. These may depend on the specifics of your cluster setup and the operating system it is running on.\n\nReview your network security policies to ensure that they are properly configured and do not allow unauthorized access to your Kubernetes ingress-nginx controller.\n\nBy following these steps, you will mitigate vulnerability khv025 by upgrading your Kubernetes ingress-nginx controller to a version that includes the security patch for CVE-2019-9514, applying any additional patches or configuration changes necessary to fully mitigate the vulnerability, and reviewing your network security policies to ensure that they are properly configured and do not allow unauthorized access to your Kubernetes ingress-nginx controller.",
    "khv026":"Sure, here are the steps and commands you can follow to fix vulnerability khv026:\n\nUpgrade your Kubernetes cluster to a version that includes the patch for CVE-2019-11247. The fix was released in Kubernetes versions 1.13.9, 1.14.5, 1.15.2, and later. You should upgrade to the latest stable version of Kubernetes that is compatible with your environment.\n\nApply any additional patches or configuration changes necessary to fully mitigate the vulnerability. These may depend on the specifics of your cluster setup and the operating system it is running on.\n\nReview your RBAC policies to ensure that they are properly configured and do not allow unauthorized access to cluster scoped resources.\n\nBy following these steps, you will mitigate vulnerability khv026 by upgrading your Kubernetes cluster to a version that includes the security patch for CVE-2019-11247, applying any additional patches or configuration changes necessary to fully mitigate the vulnerability, and reviewing your RBAC policies to ensure that they are properly configured and do not allow unauthorized access to cluster scoped resources.",
    "khv027":"Sure, here are the steps and commands you can follow to fix vulnerability khv027:\n\nUpgrade your kubectl client to a version that includes the patch for CVE-2019-11246. The fix was released in kubectl versions 1.13.10, 1.14.6, 1.15.3, and later. You should upgrade to the latest stable version of kubectl that is compatible with your environment.\n\nApply any additional patches or configuration changes necessary to fully mitigate the vulnerability. These may depend on the specifics of your cluster setup and the operating system it is running on.\n\nBy following these steps, you will mitigate vulnerability khv027 by upgrading your kubectl client to a version that includes the security patch for CVE-2019-11246, applying any additional patches or configuration changes necessary to fully mitigate the vulnerability.",
    "khv028":"Sure, here are the specific commands you can follow to fix vulnerability khv028:\n\nCheck the version of kubectl currently installed on your system:\nkubectl version --client\nDownload and install the latest stable version of kubectl for your operating system, following the instructions provided by the Kubernetes documentation:\ncurl -LO 'https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl'\nchmod +x ./kubectl\nsudo mv ./kubectl /usr/local/bin/kubectl\nVerify that the new version of kubectl is installed and has replaced the old version:\nkubectl version --client\nBy following these steps, you will mitigate vulnerability khv028 by upgrading your kubectl client to a version that includes the security patch for CVE-2019-1002101, and verifying that the new version of kubectl is installed and has replaced the old version.",
    "khv029":"Sure, here are the steps you can follow to fix vulnerability khv029:\n\nSecure your Kubernetes Dashboard by following the official Kubernetes documentation on how to secure the Dashboard with authentication and authorization.\n\nIf you do not need to use the Dashboard, consider disabling it entirely to reduce the attack surface of your Kubernetes cluster.\n\nBy following these steps, you will mitigate vulnerability khv029 by securing your Kubernetes Dashboard with authentication and authorization or disabling it entirely if it is not needed. No code is required for this vulnerability.",
    "khv030":"Sure, here are the steps you can follow to fix vulnerability khv030:\n\nConfigure your Kubernetes DNS servers to use TLS (Transport Layer Security) encryption to prevent DNS spoofing attacks.\n\nTo enable DNS over TLS for CoreDNS, add the following configuration to your CoreDNS ConfigMap:\n\ntls example.org {\n    crt /path/to/cert.pem\n    key /path/to/key.pem\n}\nEnsure that your client applications support DNS over TLS by configuring them to use the dns:// protocol with port 853.\nBy following these steps, you will mitigate vulnerability khv030 by configuring your Kubernetes DNS servers to use TLS encryption to prevent DNS spoofing attacks and ensuring that your client applications support DNS over TLS. The code snippet above shows an example of how to configure CoreDNS to use TLS.",
    "khv031":"Sure, here are the steps you can follow to fix vulnerability khv031:\n\nEnsure that your etcd cluster is only accepting connections from the Kubernetes API server by setting the --trusted-ca-file flag on each etcd instance to point to the CA certificate used by the Kubernetes API server.\n\nVerify that the etcd cluster is configured correctly by running the following command from a node in the Kubernetes cluster:\n\nETCDCTL_API=3 etcdctl --endpoints=https://[etcd-endpoint]:2379 --ca-file /etc/kubernetes/pki/etcd/ca.crt member list\n\nEnsure that etcd access is secured with proper authentication and authorization mechanisms as recommended by the official Kubernetes documentation.\n\nBy following these steps, you will mitigate vulnerability khv031 by ensuring your etcd cluster is only accepting connections from the Kubernetes API server using the --trusted-ca-file flag, verifying that the etcd cluster is configured correctly, and securing etcd access with proper authentication and authorization mechanisms. The code snippet above shows an example of how to verify that the etcd cluster is configured correctly.",
    "khv032":"Sure, here are the steps you can follow to fix vulnerability khv032:\n\nEnsure that your etcd cluster is only accepting connections from the Kubernetes API server by setting the --trusted-ca-file flag on each etcd instance to point to the CA certificate used by the Kubernetes API server.\n\nVerify that the etcd cluster is configured correctly by running the following command from a node in the Kubernetes cluster:\n\nETCDCTL_API=3 etcdctl --endpoints=https://[etcd-endpoint]:2379 --ca-file /etc/kubernetes/pki/etcd/ca.crt member list\n\nEnsure that etcd access is secured with proper authentication and authorization mechanisms as recommended by the official Kubernetes documentation.\n\nBy following these steps, you will mitigate vulnerability khv032 by ensuring your etcd cluster is only accepting connections from the Kubernetes API server using the --trusted-ca-file flag, verifying that the etcd cluster is configured correctly, and securing etcd access with proper authentication and authorization mechanisms. The code snippet above shows an example of how to verify that the etcd cluster is configured correctly.",
    "khv033":"Sure, here are the steps you can follow to fix vulnerability khv033:\n\nDisable etcd version disclosure by setting the --enable-pprof=false flag on the etcd instances.\n\nEnable authentication and authorization mechanisms for etcd access as recommended by the official Kubernetes documentation.\n\nKeep your etcd cluster up-to-date with the latest security patches and updates to minimize the risk of known vulnerabilities being exploited.\n\nBy following these steps, you will mitigate vulnerability khv033 by disabling etcd version disclosure, enabling authentication and authorization mechanisms for etcd access, and keeping your etcd cluster up-to-date with the latest security patches and updates. The code snippet above shows an example of how to disable etcd version disclosure.",
    "khv034":"Sure, here are the steps you can follow to fix vulnerability khv034:\n\nEnsure that your etcd cluster is only accessible over HTTPS by setting the --cert-file and --key-file flags on each etcd instance to point to the SSL certificate and private key used for HTTPS access.\n\nVerify that the etcd cluster is configured correctly by running the following command from a node in the Kubernetes cluster:\n\nETCDCTL_API=3 etcdctl --endpoints=https://[etcd-endpoint]:2379 --cacert /etc/kubernetes/pki/etcd/ca.crt --cert /etc/kubernetes/pki/etcd/server.crt --key /etc/kubernetes/pki/etcd/server.key member list\n\nEnsure that etcd access is secured with proper authentication and authorization mechanisms as recommended by the official Kubernetes documentation.\n\nBy following these steps, you will mitigate vulnerability khv034 by ensuring that your etcd cluster is only accessible over HTTPS using the --cert-file and --key-file flags, verifying that the etcd cluster is configured correctly, and securing etcd access with proper authentication and authorization mechanisms. The code snippet above shows an example of how to verify that the etcd cluster is configured correctly.",
    "khv036":"Sure, here are the steps you can follow to fix vulnerability khv036:\n\nDisable anonymous authentication for kubelet by setting the --anonymous-auth=false flag on each kubelet instance.\n\nConfigure authentication mechanisms for kubelet access using either the --client-ca-file or --authentication-token-webhook flags as recommended by the official Kubernetes documentation.\n\nEnsure that kubelet access is secured with proper authentication and authorization mechanisms.\n\nBy following these steps, you will mitigate vulnerability khv036 by disabling anonymous authentication for kubelet, configuring authentication mechanisms for kubelet access using either the --client-ca-file or --authentication-token-webhook flags, and ensuring that kubelet access is secured with proper authentication and authorization mechanisms. The code snippet above shows an example of how to disable anonymous authentication for kubelet.",
    "khv037":"Sure, here are the steps you can follow to fix vulnerability khv037:\n\nDisable the --enable-debugging-handlers flag on each kubelet instance to prevent container logs from being leaked via the /containerLogs endpoint.\n\nEnsure that kubelet access is secured with proper authentication and authorization mechanisms as recommended by the official Kubernetes documentation.\n\nBy following these steps, you will mitigate vulnerability khv037 by disabling the --enable-debugging-handlers flag on each kubelet instance to prevent container logs from being leaked via the /containerLogs endpoint, and ensuring that kubelet access is secured with proper authentication and authorization mechanisms. The code snippet above shows an example of how to disable the --enable-debugging-handlers flag for kubelet.",
    "khv038":"Sure, here are the steps you can follow to fix vulnerability khv038:\n\nDisable the --enable-debugging-handlers flag on each kubelet instance to prevent information about running pods from being leaked via the /runningpods endpoint.\n\nEnsure that kubelet access is secured with proper authentication and authorization mechanisms as recommended by the official Kubernetes documentation.\n\nBy following these steps, you will mitigate vulnerability khv038 by disabling the --enable-debugging-handlers flag on each kubelet instance to prevent information about running pods from being leaked via the /runningpods endpoint, and ensuring that kubelet access is secured with proper authentication and authorization mechanisms. The code snippet above shows an example of how to disable the --enable-debugging-handlers flag for kubelet.",
    "khv039":"Sure, here are the steps you can follow to fix vulnerability khv039:\n\nDisable the --enable-debugging-handlers flag on each kubelet instance to prevent an attacker from running arbitrary commands on a container via the kubelet’s /exec endpoint.\n\nEnsure that kubelet access is secured with proper authentication and authorization mechanisms as recommended by the official Kubernetes documentation.\n\nBy following these steps, you will mitigate vulnerability khv039 by disabling the --enable-debugging-handlers flag on each kubelet instance to prevent an attacker from running arbitrary commands on a container via the kubelet’s /exec endpoint, and ensuring that kubelet access is secured with proper authentication and authorization mechanisms. The code snippet above shows an example of how to disable the --enable-debugging-handlers flag for kubelet.",
    "khv040":"Sure, here are the steps you can follow to fix vulnerability khv040:\n\nDisable the --enable-debugging-handlers flag on each kubelet instance to prevent an attacker from running arbitrary commands on a container via the kubelet’s /run endpoint.\n\nEnsure that kubelet access is secured with proper authentication and authorization mechanisms as recommended by the official Kubernetes documentation.\n\nBy following these steps, you will mitigate vulnerability khv040 by disabling the --enable-debugging-handlers flag on each kubelet instance to prevent an attacker from running arbitrary commands on a container via the kubelet’s /run endpoint, and ensuring that kubelet access is secured with proper authentication and authorization mechanisms. The code snippet above shows an example of how to disable the --enable-debugging-handlers flag for kubelet.",
    "khv041":"Sure, here are the steps you can follow to fix vulnerability khv041:\n\nDisable the --enable-debugging-handlers flag on each kubelet instance to prevent an attacker from reading and writing data from a pod via the kubelet’s /portForward endpoint.\n\nEnsure that kubelet access is secured with proper authentication and authorization mechanisms as recommended by the official Kubernetes documentation.\n\nBy following these steps, you will mitigate vulnerability khv041 by disabling the --enable-debugging-handlers flag on each kubelet instance to prevent an attacker from reading and writing data from a pod via the kubelet’s /portForward endpoint, and ensuring that kubelet access is secured with proper authentication and authorization mechanisms. The code snippet above shows an example of how to disable the --enable-debugging-handlers flag for kubelet.",
    "khv042":"Sure, here are the steps you can follow to fix vulnerability khv042:\n\nDisable the --enable-debugging-handlers flag on each kubelet instance to prevent an attacker from attaching to a running container via a websocket on the kubelet’s /attach endpoint.\n\nEnsure that kubelet access is secured with proper authentication and authorization mechanisms as recommended by the official Kubernetes documentation.\n\nBy following these steps, you will mitigate vulnerability khv042 by disabling the --enable-debugging-handlers flag on each kubelet instance to prevent an attacker from attaching to a running container via a websocket on the kubelet’s /attach endpoint, and ensuring that kubelet access is secured with proper authentication and authorization mechanisms. The code snippet above shows an example of how to disable the --enable-debugging-handlers flag for kubelet.",
    "khv043":"Sure, here are the steps you can follow to fix vulnerability khv043:\n\nDisable the --enable-debugging-handlers flag on each kubelet instance to prevent the kubelet from leaking its health information via the /healthz endpoint.\n\nEnsure that kubelet access is secured with proper authentication and authorization mechanisms as recommended by the official Kubernetes documentation.\n\nBy following these steps, you will mitigate vulnerability khv043 by disabling the --enable-debugging-handlers flag on each kubelet instance to prevent the kubelet from leaking its health information via the /healthz endpoint, and ensuring that kubelet access is secured with proper authentication and authorization mechanisms. The code snippet above shows an example of how to disable the --enable-debugging-handlers flag for kubelet.",
    "khv044":"Sure, here are the steps you can follow to fix vulnerability khv044:\n\nMinimize the use of privileged containers as much as possible.\n\nUse Pod Security Policies to enforce using privileged: false policy for your pods.\n\nUse RBAC to restrict access to pod security policies and ensure that only authorized users or services can create/edit/delete them.\n\nBy following these steps, you will mitigate vulnerability khv044 by minimizing the use of privileged containers, enforcing security policies to prevent privileged containers from being used, and restricting access to pod security policies. The code snippet above shows examples of how to define a privileged container and how to use Pod Security Policies to enforce using privileged: false policy.",
    "khv045":"Sure, here are the steps you can follow to fix vulnerability khv045:\n\nDisable the --enable-debugging-handlers flag on each kubelet instance to prevent system logs from being leaked via the /logs endpoint.\n\nEnsure that kubelet access is secured with proper authentication and authorization mechanisms as recommended by the official Kubernetes documentation.\n\nBy following these steps, you will mitigate vulnerability khv045 by disabling the --enable-debugging-handlers flag on each kubelet instance to prevent system logs from being leaked via the /logs endpoint, and ensuring that kubelet access is secured with proper authentication and authorization mechanisms. The code snippet above shows an example of how to disable the --enable-debugging-handlers flag for kubelet.",
    "khv046":"Sure, here are the steps you can follow to fix vulnerability khv046:\n\nDisable the --enable-debugging-handlers flag on each kubelet instance to prevent a pod running in the cluster from accessing the Kubelet’s debug/pprof/cmdline endpoint and examining how the kubelet was executed on the node.\n\nEnsure that kubelet access is secured with proper authentication and authorization mechanisms as recommended by the official Kubernetes documentation.\n\nBy following these steps, you will mitigate vulnerability khv046 by disabling the --enable-debugging-handlers flag on each kubelet instance to prevent a pod running in the cluster from accessing the Kubelet’s debug/pprof/cmdline endpoint and examining how the kubelet was executed on the node, and ensuring that kubelet access is secured with proper authentication and authorization mechanisms. The code snippet above shows an example of how to disable the --enable-debugging-handlers flag for kubelet.",
    "khv047":"Sure, here are the steps you can follow to fix vulnerability khv047:\n\nConsider disallowing running as root by using Kubernetes Pod Security Policies with MustRunAsNonRoot policy. This will prevent containers in the pod from having write access to the host's /var/log directory.\n\nConsider disallowing writable host mounts to /var/log by using Kubernetes Pod Security Policies with AllowedHostPaths policy. This will prevent containers in the pod from being able to create arbitrary files or symlink to other files on the host.\n\nUse a container runtime like Aqua that provides additional security controls for Kubernetes clusters. For example, Aqua has a Runtime Policy with Volume Blacklist and Blacklisted OS Users and Groups that can further restrict access to sensitive directories such as /var/log.\n\nBy following these steps, you will mitigate vulnerability khv047 by disallowing running as root, disallowing writable host mounts to /var/log, and using a container runtime that provides additional security controls for Kubernetes clusters. The references above provide more information on how to use Kubernetes Pod Security Policies to enforce these restrictions.",
    "khv049":"Sure, here are the steps you can follow to fix vulnerability khv049:\n\nUse a permanent and legitimate way to expose your applications such as Ingress or Load Balancer.\n\nIf you need to use kubectl proxy for temporary access to an application running in Kubernetes or to the Kubernetes API, ensure that you close the proxy immediately after use.\n\nImplement proper authentication and authorization mechanisms to secure access to your Kubernetes cluster and applications.\n\nBy following these steps, you will mitigate vulnerability khv049 by using a permanent and legitimate way to expose your applications, closing open proxies immediately after use, and ensuring proper authentication and authorization mechanisms are in place to secure access to your Kubernetes cluster and applications. The reference above provides more information on how to use kubectl proxy safely.",
    "khv050":"Sure, here are the steps you can follow to fix vulnerability khv050:\n\nExplicitly specify a Service Account for all of your workloads using serviceAccountName in Pod.Spec. This will allow you to manage the permissions of the Service Account according to the least privilege principle.\n\nConsider opting out automatic mounting of Service Account token using automountServiceAccountToken: false on ServiceAccount resource or Pod.Spec. This will prevent the Service Account token from being automatically mounted into containers in the pod, reducing the attack surface.\n\nImplement proper authentication and authorization mechanisms to secure access to your Kubernetes cluster and applications.\n\nBy following these steps, you will mitigate vulnerability khv050 by explicitly specifying a Service Account for all of your workloads, opting-out automatic mounting of SA token where possible, and ensuring proper authentication and authorization mechanisms are in place to secure access to your Kubernetes cluster and applications. The reference above provides more information on how to configure Service Accounts in Kubernetes.",
    "khv051":"Sure, here are the steps you can follow to fix vulnerability khv051:\n\nEnsure kubelet is protected by disabling anonymous access using --anonymous-auth=false flag on kubelet.\n\nAllow only legitimate users by using --client-ca-file or --authentication-token-webhook flags on kubelet.\n\nMinimize the use of privileged containers.\n\nUse Pod Security Policies to enforce using privileged: false policy.\n\nReview the RBAC permissions to Kubernetes API server for the anonymous and default service account, including bindings.\n\nEnsure node(s) runs active filesystem monitoring.\n\nSet --insecure-port=0 and remove --insecure-bind-address=0.0.0.0 in the Kubernetes API server config.\n\nRemove AlwaysAllow from --authorization-mode in the Kubernetes API server config. Alternatively, set --anonymous-auth=false in the Kubernetes API server config; this will depend on the API server version running.\n\nBy following these steps, you will mitigate vulnerability khv051 by disabling anonymous access to kubelet, allowing only legitimate users, minimizing the use of privileged containers, enforcing security policies, reviewing RBAC permissions, ensuring active filesystem monitoring, and configuring the Kubernetes API server securely. The references above provide more information on how to configure these security measures.",
    "khv052":"Sure, here are the steps you can follow to fix vulnerability khv052:\n\nEnsure kubelet is protected by disabling anonymous access using --anonymous-auth=false flag on kubelet.\n\nAllow only legitimate users by using --client-ca-file or --authentication-token-webhook flags on kubelet.\n\nDisable the readonly port by using --read-only-port=0 flag on kubelet.\n\nBy following these steps, you will mitigate vulnerability khv052 by disabling anonymous access to kubelet, allowing only legitimate users, and disabling the readonly port. The references above provide more information on how to configure these security measures.",
    "khv053":"Sure, here are the steps you can follow to fix vulnerability khv053:\n\nLimit access to the instance metadata service by using a local firewall such as iptables to disable access from some or all processes/users to the instance metadata service. This will prevent attackers from accessing sensitive information about the environment.\n\nDisable the metadata service (via instance metadata options or IAM), or at a minimum enforce the use IMDSv2 on an instance to require token-based access to the service.\n\nModify the HTTP PUT response hop limit on the instance to 1. This will only allow access to the service from the instance itself rather than from within a pod.\n\nBy following these steps, you will mitigate vulnerability khv053 by limiting access to the instance metadata service, disabling the metadata service, enforcing the use of IMDSv2 to require token-based access to the service, and modifying the HTTP PUT response hop limit on the instance to prevent attackers from accessing sensitive information about the environment. The references above provide more information on how to configure these security measures in AWS.",
    }
    return main_dict[idn]


def enhanced_logging(filetext):
    # progress()
    print("\nThis is the enhanced version of kube hunter log which gives you all necessary information about vulnerabilities and how to resolve it as well!\n")

    ids = []
    # ids = ['khv002', 'khv003', 'khv004', 'khv005', 'khv006', 'khv007', 'khv020', 'khv021', 'khv022', 'khv023', 'khv024', 'khv025', 'khv026', 'khv027', 'khv028', 'khv029', 'khv030', 'khv031', 'khv032', 'khv033', 'khv034', 'khv036', 'khv037', 'khv038', 'khv039', 'khv040', 'khv041', 'khv042', 'khv043', 'khv044', 'khv045', 'khv046', 'khv047', 'khv049', 'khv050', 'khv051', 'khv052', 'khv053']

    for i in range(0,len(filetext)-2):
        if(filetext[i]=='K' and filetext[i+1]=='H' and filetext[i+2]=='V'):
            ids.append(filetext[i:i+6])
            
            
    vulnerability_main = {}

    for ind in ids:
        ind = str(ind).lower() 
        vulnerability_solution = solutions(ind)    
        page = requests.get(f'https://avd.aquasec.com/misconfig/kubernetes/{ind}/')
        page_str = f'https://avd.aquasec.com/misconfig/kubernetes/{ind}/'

        page1 = urllib2.urlopen(page_str)

        soup = BeautifulSoup(page1, 'html.parser')

        tree = html.fromstring(page.content) 

        vulnerability_name = tree.xpath('/html/body/div[3]/div/div/div[2]/div/div/h3[1]/text()')[0]

        issue_description = tree.xpath('/html/body/div[3]/div/div/div[2]/div/div/p[1]/text()')[0]

        remediation1 = tree.xpath('/html/body/div[3]/div/div/div[2]/div/div/p[2]/text()')

        severity1 = tree.xpath('/html/body/div[3]/div/div/div[1]/div/div/div[1]/div/div/div/div[1]/div/text()')

        severity = "sv"

        if(severity1!=[]):
            severity = tree.xpath('/html/body/div[3]/div/div/div[1]/div/div/div[1]/div/div/div/div[1]/div/text()')[0]
        else:
            severity = "Severity status not stated in website"

        remediation ="kh"
        if(remediation1!=[]):
            remediation = tree.xpath('/html/body/div[3]/div/div/div[2]/div/div/p[2]/text()')[0]
        else:
            remediation = "No remedy given!"


        remedy_links = []
        references = []

        i=0
        flag =1
        for link in soup.findAll('a'):
            i = i+1
            a = str(link.get('href'))
            if(i>=11):
                if(a=='None'):
                    flag=0
                    continue
                s= 'www.aquasec.com'
                if(a.find(s)!=-1):
                    break
                if(flag==0):
                    references.append(a)
                else:
                    remedy_links.append(a)


        if(remediation==[]):
            remediation = "No content given in website!"


        if(remedy_links==[]):
            remedy_links = "No remedy links given in website!"


        if(references==[]):
            references = "No other links given in website!"

        severity_level = 0
        if(severity=="LOW"):
            severity_level = 1
        elif(severity=="MEDIUM"):
            severity_level = 2
        elif(severity=="HIGH"):
            severity_level = 3
        else:
            severity_level = 4
        vulnerability_report = {
            "vulnerability_id" : ind,
            "vulnerability_name" : vulnerability_name,
            "severity" : severity,
            "issue_description" : issue_description,
            "remediation" : remediation,
            "remedy_links" : remedy_links,
            "references": references,
            "vulnerability_solution":vulnerability_solution,
            "severity_level":severity_level
        }


        vulnerability_main[ind] = vulnerability_report

    # vulnerability_main_json = json.dumps(vulnerability_main,indent=4)
    vulnerability_main_json = vulnerability_main
    save_file = open("file.json", "w")  
    json.dump(vulnerability_main_json, save_file)  
    save_file.close()  

    response = requests.post(json_bin_link, json=vulnerability_main_json)

    # for i in trange(100, desc="Running", unit="iterations"):
    #     time.sleep(0.1)
    # tqdm.write("Completed")

textfile = open('kube-hunter-logs.txt', 'r')
filetext = textfile.read()
textfile.close()
enhanced_logging(filetext)


