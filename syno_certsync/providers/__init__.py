from .aliyun import AliyunFetcher
from .tencent import TencentFetcher
from .aws import AwsFetcher

# Providers whose API lets us download an already issued cert WITH its private key.
FETCHERS = {
    "aliyun": AliyunFetcher,
    "tencent": TencentFetcher,
    "aws": AwsFetcher,
}

# Providers usable for ACME DNS-01 issuance (acme.sh dns hook names).
# Cloudflare / GoDaddy do not expose private keys of issued certs, and Huawei
# export is not implemented yet, so these are ACME-only.
ACME_PROVIDERS = {
    "aliyun": "dns_ali",
    "tencent": "dns_tencent",
    "cloudflare": "dns_cf",
    "huawei": "dns_huaweicloud",
    "godaddy": "dns_gd",
    "aws": "dns_aws",
}
