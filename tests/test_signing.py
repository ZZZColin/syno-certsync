"""Signature algorithms checked against published reference vectors."""
import unittest

from syno_certsync.providers.aliyun import rpc_signature
from syno_certsync.providers.tencent import tc3_signature
from syno_certsync.providers.aws import sigv4


class SigningVectors(unittest.TestCase):
    def test_tencent_tc3_doc_example(self):
        # Tencent Cloud "signature v3" doc example (cvm DescribeInstances, SecretKey shown as 32 asterisks)
        payload = '{"Limit": 1, "Filters": [{"Values": ["\\u672a\\u547d\\u540d"], "Name": "instance-name"}]}'
        sig, scope = tc3_signature(
            "*" * 32, "cvm", 1551113065,
            "content-type:application/json; charset=utf-8\nhost:cvm.tencentcloudapi.com\nx-tc-action:describeinstances\n",
            "content-type;host;x-tc-action", payload)
        self.assertEqual(scope, "2019-02-25/cvm/tc3_request")
        self.assertEqual(sig, "10b1a37a7301a02ca19a647ad722d5e43b4b3cff309d421d85b46093f6ab6c4f")

    def test_aws_sigv4_get_vanilla(self):
        # AWS Signature V4 test suite, case "get-vanilla"
        sig, signed, scope = sigv4(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "GET", "/", "",
            {"host": "example.amazonaws.com", "x-amz-date": "20150830T123600Z"},
            "", "us-east-1", "service", "20150830T123600Z")
        self.assertEqual(scope, "20150830/us-east-1/service/aws4_request")
        self.assertEqual(signed, "host;x-amz-date")
        self.assertEqual(sig, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")

    def test_aliyun_rpc_doc_example(self):
        # Aliyun RPC signature doc example (ECS DescribeRegions)
        params = {
            "Format": "XML", "AccessKeyId": "testid", "Action": "DescribeRegions",
            "SignatureMethod": "HMAC-SHA1", "SignatureNonce": "3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf",
            "SignatureVersion": "1.0", "Timestamp": "2016-02-23T12:46:24Z", "Version": "2014-05-26"}
        _, sig = rpc_signature(params, "testsecret")
        self.assertEqual(sig, "OLeaidS1JvxuMvnyHOwuJ+uX5qY=")


if __name__ == "__main__":
    unittest.main()
