#coding:utf-8
import unittest
import pytest

from ks3.auth import add_auth_header
from ks3.connection import Connection
from ks3.bucket import Bucket
from ks3.key import Key
from ks3.acl import Policy, ACL, Grant
from ks3.user import User

ak = 'YOUR_ACCESS_KEY'
sk = 'YOUR_SECRET_KEY'
conn = Connection(ak, sk, host="")
test_bucket = 'sdktestt'
test_key = 'test_key'

# ------------------------------------Auth relative test------------------------------
class TestAuthToken(unittest.TestCase):
    def test_auth_token(self):
        headers = {}
        method = "POST"
        bucket = test_bucket
        key = test_key
        query_args = {'upload': None}
        add_auth_header(ak, sk, headers, method, bucket, key, query_args)
        print(headers['Authorization'])

# ------------------------------------bucket relative test------------------------------
class TestBucket(unittest.TestCase):

    # Get all buckets
    def test_get_all_buckets(self):
        buckets = conn.get_all_buckets()
        for b in buckets:
            print(b.name)
            assert isinstance(b, Bucket)

    # Get keys within specified bucket
    def test_get_bucket(self):
        bucket = conn.get_bucket(test_bucket)
        keys = bucket.list()
        for k in keys:
            print(k.name)

    # Get bucket location
    def test_get_bucket_location(self):
        loc = conn.get_bucket_location(test_bucket)
        print(loc)

class TestDeleteBucket(unittest.TestCase):
    """
    test delete bucket
    """
    def test_delete_bucket(self):
        b = conn.get_bucket(test_bucket)
        for k in b.list():
            k.delete()
        conn.delete_bucket(test_bucket)

class TestCreateBucket(unittest.TestCase):
    # Create one bucket
    def test_create_bucket(self):
        bucket = conn.create_bucket(test_bucket)
        print(bucket.name)
        # assert "sdktest" == bucket.name

class TestListMulUploads(unittest.TestCase):
    def test_list_multipart_uploads(self):
        bucket = conn.get_bucket(test_bucket)
        parts = bucket.list_multipart_uploads()
        for part in parts:
            print(part.to_xml())
            print(part)

class TestGetBucketLoggingStatus(unittest.TestCase):
    def test_get_bucket_logging_status(self):
        bucket = conn.get_bucket(test_bucket)
        print(bucket.get_logging_status())

class TestSetBucketLogging(unittest.TestCase):
    def test_set_bucket_logging(self):
        bucket = conn.get_bucket(test_bucket)
        # logging is kind of xml string.
        from ks3.bucketlogging import BucketLogging
        target = test_bucket
        prefix = "test_bucket_access_log"
        grants = []
        logging = BucketLogging(target, prefix, grants).to_xml()
        bucket.set_xml_logging(logging, headers={'content-type': 'text/plain'})

class TestDisableBucketLogging(unittest.TestCase):
    def test_disable_bucket_logging(self):
        bucket = conn.get_bucket(test_bucket)
        bucket.disable_logging(headers={'content-type': 'text/plain'})


class TestEnableBucketLogging(unittest.TestCase):
    def test_enable_bucket_logging(self):
        bucket = conn.get_bucket(test_bucket)
        bucket.enable_logging(bucket, headers={'content-type': 'text/plain'})


class TestGetBucketAcl(unittest.TestCase):
    def test_get_bucket_acl(self):
        bucket = conn.get_bucket(test_bucket)
        print(bucket.get_acl())


class TestSetBucketAcl(unittest.TestCase):
    def test_set_bucket_acl(self):
        bucket = conn.get_bucket(test_bucket)
        p = Policy()
        acl = ACL()
        grant = Grant(id='test1', display_name='test1', type='CanonicalUser', permission='READ')
        acl.add_grant(grant)
        p.owner = User(id='1234567890', display_name='test')
        p.acl = acl
        bucket.set_acl(acl_or_str=p, headers={'content-type': 'text/plain'})

# ------------------------------------object relative test------------------------------
class TestGetKeyAcl(unittest.TestCase):
    def test_get_acl(self):
        bucket = conn.get_bucket(test_bucket)
        policy = bucket.get_acl()
        # print policy.to_xml()
        for grant in policy.acl.grants:
            print(grant.permission, grant.display_name, grant.email_address, grant.id)

# ------------------------------------upload object test------------------------------
class TestUploadObject(unittest.TestCase):
    # Create a object key in specified bucket
    def test_create_object(self):
        bucket = conn.get_bucket(test_bucket)
        key = bucket.new_key(test_key)
        print(key.set_contents_from_filename("D:/upload_test.txt", policy="public-read-write"))

class TestGetObject(unittest.TestCase):
    def test_get_object(self):
        bucket = conn.get_bucket(test_bucket)
        key = bucket.get_key(test_key)
        if key:
            key.get_contents_to_filename("D:/download_test.txt")
            #s = key.get_contents_as_string();
            #print(s)
        else:
            print("Object key is NOT exist.")

    def test_head_object(self):
        pass

class TestEncryptionUploadObject(unittest.TestCase):
    # Create a object key in specified bucket
    def test_encryption_upload(self):
        from ks3.encryption import Crypts
        Crypts.generate_key('D:/', 'key.txt')
        c = Connection(ak, sk, host="", is_secure=False, domain_mode=False, local_encrypt=True, local_key_path="D:/key.txt")
        b = c.get_bucket(test_bucket)
        #put
        kw = b.new_key(test_key)
        ret = kw.set_contents_from_string("some thing")
        #get
        get_key = b.get_key(test_key)
        s = get_key.get_contents_as_string()
        print("Result:", s)

class TestKeyLink(unittest.TestCase):
    def test_key_link(self):
        bucket = conn.get_bucket(test_bucket)
        key = bucket.get_key(test_key)
        # print key.generate_url(expires_in=1435320559, expires_in_absolute=True)
        print(key.generate_url(expires_in=10000, expires_in_absolute=False))

class TestSetKeyAcl(unittest.TestCase):
    """
    AccessControlPolicy:
    AccessControlList:
    DisplayName:
    Grant: Container for the grantee and his or her permissions.
    Grantee: The subject whose permissions are being set
    ID: ID of the bucket owner, or the ID of the grantee.
    Owner: Container for the bucket owner's display name and ID.
    Permission:[FULL_CONTROL | WRITE | WRITE_ACP | READ | READ_ACP]
    """

    def test_set_acl(self):
        owner = User(id='1234567890', display_name='test')
        acl = ACL()
        grant = Grant()
        grant.permission = "READ"
        grant.display_name = "test"
        grant.email_address = "test@ksc.com"
        grant.type = 'CanonicalUser'
        acl.add_grant(grant)
        policy = Policy()
        policy.owner = owner
        policy.acl = acl
        bucket = conn.get_bucket(test_bucket)
        # ret = bucket.set_acl("public-read-write", test_key)
        ret = bucket.set_xml_acl(policy.to_xml(), test_key, headers={'content-type': 'text/plain'})
        print(ret)

class TestMultipartUploadObject(unittest.TestCase):
    def test_multipart_upload(self):
        import math, os
        import time
        from filechunkio import FileChunkIO
        bucket = conn.get_bucket(test_bucket)

        source_path = 'D:/test.txt'
        source_size = os.stat(source_path).st_size

        mp = bucket.initiate_multipart_upload(os.path.basename(source_path), policy="public-read-write")
        print(mp.id)

        # chunk_size = 5242880
        chunk_size = 5242880
        chunk_count = int(math.ceil(source_size * 1.0 / chunk_size * 1.0))

        try:
            for i in range(chunk_count):
                offset = chunk_size * i
                bytes = min(chunk_size, source_size - offset)
                with FileChunkIO(source_path, 'r', offset=offset, bytes=bytes) as fp:
                    mp.upload_part_from_file(fp, part_num=i + 1)
            ret = mp.complete_upload()
            if ret and ret.status == 200:
                print("上传成功")
        except:
            pass  # 异常处理

class TestEncryptionMultipartUploadObject(unittest.TestCase):
    def test_encryption_multipart_upload(self):
        import math, os
        from ks3.encryption import Crypts
        Crypts.generate_key('D:/', 'key.txt')
        c = Connection(ak, sk, host="", is_secure=False, domain_mode=False,
                          local_encrypt=True, local_key_path="D:/key.txt")
        from filechunkio import FileChunkIO
        bucket = c.get_bucket(test_bucket)

        source_path = 'D:/1.exe'
        source_size = os.stat(source_path).st_size
        mp = bucket.initiate_multipart_upload(os.path.basename(source_path), calc_encrypt_md5=False)
        chunk_size = 5242880
        chunk_count = int(math.ceil(source_size*1.0 / chunk_size*1.0))
        print(chunk_count)
        try:
            for i in range(chunk_count):
                offset = chunk_size * i
                last = False
                bytes = min(chunk_size, source_size - offset)
                if i + 1 == chunk_count:
                    last = True
                with FileChunkIO(source_path, 'r', offset=offset,bytes=bytes) as fp:
                    mp.upload_part_from_file(fp, part_num=i + 1, is_last_part=last)

            ret = mp.complete_upload()
            if ret and ret.status == 200:
                print("上传成功")
        except:
            pass

class TestAbortMultipartUpload(unittest.TestCase):
    def test_abort_multipart_upload(self):
        bucket = conn.get_bucket(test_bucket)
        for p in bucket.get_all_multipart_uploads():
            # delete all parts
            print(p.id)
            print(p.cancel_upload())

class TestListPart(unittest.TestCase):
    def test_list_part(self):
        bucket = conn.get_bucket(test_bucket)
        for p in bucket.get_all_multipart_uploads():
            print(p.id)

class TestDeleteObject(unittest.TestCase):
    def test_delete_object(self):
        bucket = conn.get_bucket(test_bucket)
        print(bucket.delete_key(test_key))

if __name__ == '__main__':
    unittest.main()
