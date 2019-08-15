##  KS3 SDK for python使用指南
---
###目录
* [开发前准备](#开发前准备)
 * [安装依赖模块](#安装依赖模块)
 * [安装python sdk](#安装python-sdk)
 * [初始化connection](#初始化connection)
 * [运行环境](#运行环境)


* [SDK介绍及使用](#SDK介绍及使用)
 * [资源管理操作](#资源管理操作)
 * [Service操作](#Service操作)
 * [Bucket操作](#Bucket操作)
 * [Object操作](#Object操作)
 * [客户端文件加密](#客户端文件加密)

---

###  <span id="开发前准备">开发前准备</span>
#### <span id="安装依赖模块">安装依赖模块</span>

    pip install six


#### <span id="安装python-sdk"> 安装python sdk</span>
##### 在线安装

    pip install ks3sdk

##### 本地安装

1、通过git下载SDK到本地

    git clone https://github.com/ks3sdk/ks3-python-sdk.git


2、进入ks3-python-sdk目录

    cd  ks3-python-sdk

3、安装SDK

    python setup.py install

#### <span id="初始化connection">初始化connection</span>

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False)

参数说明

* ak：金山云提供的ACCESS KEY ID

* sk：金山云提供的SECRET KEY ID

* host：金山云提供的各个Region的域名（例 ks3-cn-beijing.ksyun.com）,具体定义可参考 [API接口文档-Region(区域)](https://docs.ksyun.com/directories/1782)。也可以是用户自定义域名，如果是用户自定义域名，需要将domain_mode设置为True。

* is_secure：是否通过HTTPS协议访问Ks3，True:启用 False:关闭。

* domain_mode：是否使用自定义域名访问Ks3（host填写自定义域名），True:是 False:否。

####  <span id="运行环境">运行环境</span>
适用于2.6、2.7、3.3、3.4、3.5、3.6、3.7版本。


###  <span id="SDK介绍及使用">SDK介绍及使用</span>

####  <span id="资源管理操作">资源管理操作</span>
* [List Buckets](#list-bucket) 列出客户所有的Bucket信息
* [Create Bucket](#create-bucket) 创建一个新的Bucket
* [Delete Bucket](#delete-bucket) 删除指定Bucket
* [Get Bucket ACL](#get-bucket-acl) 获取Bucket的ACL
* [Put Bucket ACL](#put-bucket-acl) 设置Bucket的ACL
* [Head Object](#head-object) 获取Object元信息
* [Get Object](#get-object) 下载Object数据
* [Put Object](#put-object) 上传Object数据
* [Put Object Copy](#put-object-copy) 复制Object数据
* [Delete Object](#delete-object) 删除Object数据
* [List Object](#list-object) 列举Bucket内的Object
* [Get Object ACL](#get-object-acl) 获得Object的acl
* [Put Object ACL](#put-object-acl) 上传object的acl
* [Upload Part](#upload-part) 上传分块
* [Generate URL](#generate-url) 生成下载外链
### <span id="Service操作">Service操作</span>

#### <span id="list-bucket">List Buckets：</span>

*列出客户所有的 Bucket 信息*

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False)
    buckets = c.get_all_buckets()
    for b in buckets:
    	print(b.name)

### <span id="Bucket操作">Bucket操作</span>

#### <span id="create-bucket">Create Bucket： </span>

*创建一个新的Bucket*

在建立了连接后，可以创建一个bucket。bucket在s3中是一个用于储存key/value的容器。用户可以将所有的数据存储在一个bucket里，也可以为不同种类数据创建相应的bucket。

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False)
    bucket_name = "YOUR_BUCKET_NAME"
    b = c.create_bucket(bucket_name)

注：这里如果出现409 conflict错误，说明请求的bucket name有冲突，因为bucket name是全局唯一的

#### <span id="delete-bucket">Delete Bucket:</span>

*删除指定Bucket*

删除一个bucket可以通过delete_bucket方法实现。

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False)
    bucket_name = "YOUR_BUCKET_NAME" 
    c.delete_bucket(bucket_name)

如果bucket下面存在key，那么需要首先删除所有key

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False)
    bucket_name = "YOUR_BUCKET_NAME"
    b = c.get_bucket(bucket_name)
    for k in b.list():
        k.delete()
    c.delete_bucket(bucket_name)

#### <span id="get-bucket-acl">Get Bucket ACL:</span>

*获取Bucket的ACL*

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False)
    bucket_name = "YOUR_BUCKET_NAME"
    b = c.get_bucket(bucket_name)
    policy = b.get_acl()
    for grant in policy.acl.grants:
    	print(grant.permission, grant.display_name, grant.email_address, grant.id)   

#### <span id="put-bucket-acl">Put Bucket ACL:</span>

*设置Bucket的ACL*

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False)

    bucket_name = "YOUR_BUCKET_NAME"
    b = c.get_bucket(bucket_name)
    #设置bucket的权限, private or public-read or public-read-write
    b.set_acl("public-read")

### <span id="Object操作">Object操作</span>

#### <span id="head-object">Head Object:</span>
*获取Object元信息*

获取Object元数据信息（大小、最后更新时间等）

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False)

    bucket_name = "YOUR_BUCKET_NAME"
    key_name = "YOUR_KEY_NAME"
    b = c.get_bucket(bucket_name)
    try:
    	k = b.get_key(key_name)
    	if k:
             print(k.name, k.size, k.last_modified)
    except:
    	pass  

#### <span id="get-object">Get Object：</span>
*下载该Object数据*
 
下载object，并且作为字符串返回

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False)

    bucket_name = "YOUR_BUCKET_NAME"
    key_name = "YOUR_KEY_NAME"
    b = c.get_bucket(bucket_name)
    try:
	    k = b.get_key(key_name)
	    s = k.get_contents_as_string().decode()
	    print(s)
    except:
	    pass

下载object，并且保存到文件中

	#保存到文件
	k.get_contents_to_filename("SAVED_FILE_PATH")

#### <span id="put-object">Put Object</span>
*上传Object数据* 

将指定目录下某一个文件上传，同时可以指定文件ACL

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False)  

    bucket_name = "YOUR_BUCKET_NAME"
    key_name = "YOUR_KEY_NAME"
    try: 
	    b = c.get_bucket(bucket_name)
	    k = b.new_key(key_name)
	    #object policy : 'private' or 'public-read'
	    ret=k.set_contents_from_filename("YOUR_SOURCE_FILE_PATH", policy="private")
	    if ret and ret.status == 200:
	    	print("上传成功")
    except:
	    pass #异常处理   

将字符串作为value上传

    k.set_contents_from_string('YOUR_FILE_CONTENTS')

上传回调
需要设置`x-kss-callbackurl`和`x-kss-callbackbody`请求头，详见文档[上传回调处理](https://docs.ksyun.com/documents/956)。
```
headers = {"x-kss-callbackurl": "Callback_URL","x-kss-callbackbody":"objectKey=${key}&etag=${etag}&uid=123"}
ret = k.set_contents_from_filename(filepath, headers=headers)
```

以低频存储方式上传
```
//x-kss-storage-class有效值为"STANDARD"、"STANDARD_IA"。"STANDARD"表示标准存储，"STANDARD_IA"表示低频存储，如果不指定，默认为标准存储。
headers = {"x-kss-storage-class": "STANDARD_IA"}
resp = k.set_contents_from_filename(filepath, policy="private", headers=headers)
```
 
#### <span id="put-object-copy">Put Object Copy:</span>
*复制Object数据*

将指定Bucket下的文件复制到本Bucket下（需要对源Bucket下的文件具有读权限）

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False) 
   
    bucket_name = "YOUR_DST_BUCKET_NAME"
    key_name = "YOUR_DST_KEY_NAME"
    try: 
        b = c.get_bucket(bucket_name)
        b.copy_key(key_name,"YOUR_SRC_BUCKET_NAME","YOUR_SRC_KEY_NAME")
    except:
        pass
    
#### <span id="delete-object">Delete Object:</span>
*删除Object数据*

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False)  

    bucket_name = "YOUR_BUCKET_NAME"
    key_name = "YOUR_KEY_NAME"
    try: 
        b=c.get_bucket(bucket_name)
        b.delete_key(key_name)
    except:
        pass  
	
#### <span id="list-object">List Object</span>
*列举Bucket内的文件或者目录*

    from ks3.connection import Connection
    from ks3.prefix import Prefix
    from ks3.key import Key
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False) 

    bucket_name = "YOUR_BUCKET_NAME"
    b = c.get_bucket(bucket_name)
    keys = b.list(delimiter='/')
    for k in keys:
        if isinstance(k, Key):
            print('file:%s' % k.name)
        elif isinstance(k, Prefix)
            print('dir:%s' % k.name)

*列举Bucket内指定前缀的文件*

    keys = b.list(prefix="PREFIX")

#### <span id="get-object-acl">Get Object ACL</span>
*获得Object的acl*

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False) 

    bucket_name = "YOUR_BUCKET_NAME"
    key_name = "YOUR_KEY_NAME"  
    b = c.get_bucket(bucket_name)
    policy = b.get_acl(key_name)
    print(policy.to_xml())

#### <span id="put-object-acl">Put Object ACL</span>

	#object policy : 'private' or 'public-read'
	b.set_acl("public-read", test_key)

#### <span id="upload-part">Upload Part：</span>
*分块上传*

如果你想上传一个大文件，你可以将它分成几个小份，逐个上传，ks3会按照顺序把它们合成一个最终的object。通过SDK进行分块上传能够保障数据传到ks3的正确性，无需另外做数据校验。

整个过程需要几步来完成，下面的demo程序是通过python的FileChunkIO模块来实现的。所以可能需要首先运行pip install FileChunkIO来安装。

    import math, os
    from ks3.connection import Connection
    from filechunkio import FileChunkIO
     
    # Connect to S3
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False)
    bucket_name = "YOUR_BUCKET_NAME"
    b = c.get_bucket(bucket_name)
     
    # Get file info
    source_path = 'SOURCE_FILE_PATH'
    source_size = os.stat(source_path).st_size
     
    # Create a multipart upload request
    # 此处os.path.basename(source_path)可以替换为需要设置的objectKey
    mp = b.initiate_multipart_upload(os.path.basename(source_path))
    # Use a chunk size of 50 MiB (feel free to change this)
    chunk_size = 52428800
    chunk_count = int(math.ceil(source_size // chunk_size))

    # Send the file parts, using FileChunkIO to create a file-like object
    # that points to a certain byte range within the original file. We
    # set bytes to never exceed the original file size.
    for i in range(chunk_count+1):
         offset = chunk_size * i 
         bytes = min(chunk_size, source_size - offset)
         with FileChunkIO(source_path, 'r', offset=offset,bytes=bytes) as fp: 
             mp.upload_part_from_file(fp, part_num=i + 1) 
     
    # Finish the upload
    mp.complete_upload()
以低频存储方式上传，需要在initiate_multipart_upload阶段设置
```
//x-kss-storage-class有效值为"STANDARD"、"STANDARD_IA"。"STANDARD"表示标准存储，"STANDARD_IA"表示低频存储，如果不指定，默认为标准存储。
headers = {"x-kss-storage-class": "STANDARD_IA"}
mp = b.initiate_multipart_upload(os.path.basename(source_path), policy="private", headers=headers)
```   
*获取已上传分块列表*

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False) 

    bucket_name = "YOUR_BUCKET_NAME" 
    b = c.get_bucket(bucket_name)
    for p in b.list_multipart_uploads():
        print('uploadId:%s,key:%s' % (p.id, p.key_name))
        for i in p:
            print(i.part_number, i.size, i.etag, i.last_modified)

#### <span id="generate-url">Generate URL</span>
*生成下载外链地址*

对私密属性的文件生成下载外链（该链接具有时效性）

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False) 

    bucket_name = "YOUR_BUCKET_NAME"
    key_name = "YOUR_KEY_NAME" 
    b = c.get_bucket(bucket_name)
    k = b.get_key(key_name)
    if k:
        url = k.generate_url(60) # 60s 后该链接过期
        print(url)

指定时间过期
```	
k.generate_url(1492073594,expires_in_absolute=True) # 1492073594为Unix Time
```

## <span id="客户端文件加密">客户端文件加密</span>
如果您有上传前先加密数据的需求，可以考虑使用加密模式。
### 环境要求
使用加密客户端需要安装pycrypto。
1. 可选择使用pip install pycrypto进行安装
2. 无法直接连接pypi服务的话，可选择下载[pycrypto安装包](https://pypi.python.org/pypi/pycrypto/2.6.1/)手动进行安装

### 配置密钥
您可以使用自己的密钥文件，或者选择调用我们的密钥生成方法。
1. 如果使用自己的密钥文件：请确保文件中密钥长度为16字节，如果不是16字节，程序将报错
2. 如果调用密钥生成方法：

```
from ks3.encryption import Crypts
Crypts.generate_key('your_path', 'key_name')
```
*请注意保管好您的key文件，KS3服务端将不会对客户端加密时使用的key文件进行保存，一旦丢失，文件将无法被解密。*

### 用法示例
#### PUT、GET
对put、get方法加密客户端和普通客户端用法基本一致，不同之处在于初始化Connection对象时需要多填两个参数：local_encrypt和local_key_path。local_encrypt设置为true，local_key_path设置为密钥存放在本地的地址。

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT',is_secure=False, domain_mode=False, local_encrypt=True, 
            local_key_path="your_key_path")

    b = c.get_bucket("your_bucket")
    #put
    kw = b.new_key("your_key")
    ret = kw.set_contents_from_string("some string")
    #get
    get_key = b.get_key("your_key")
    s = get_key.get_contents_as_string()
    print("Result:",s)

#### 分块上传

>注意：加密客户端的分块上传不支持对文件的并行上传！分块上传时必须依次序上传每一块，否则数据将无法解密。

示例1：使用FileChunkIO进行分块上传。与普通客户端的方法基本一致，和put一样只需在初始化时增加参数。

    c = Connection(ak, sk, host,is_secure=False, domain_mode=False, local_encrypt=True, local_key_path="your_key_path")
    #继续普通分块上传方法

示例2：自己切分文件进行分块上传。除了修改Connection的参数之外，还需在调用upload_part_from_file方法时指定is_last_part的值。

    from ks3.connection import Connection
    from filechunkio import FileChunkIO
    import math, os
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT',is_secure=False, domain_mode=False, local_encrypt=True, 
           local_key_path="your_key_path")

    b = c.get_bucket("your_bucket")
    source_path = 'SOURCE_FILE_PATH'
    source_size = os.stat(source_path).st_size
    mp = bucket.initiate_multipart_upload(os.path.basename(source_path))
    # Use a chunk size of 50 MiB (feel free to change this)
    chunk_size = 52428800
    chunk_count = int(math.ceil(source_size // chunk_size))
    for i in range(chunk_count + 1):
    	offset = chunk_size * i
        last = False
        bytes = min(chunk_size, source_size - offset)
        if i == chunk_count + 1:
            last = True
        with FileChunkIO(source_path, 'r', offset=offset,
                         bytes=bytes) as fp:
            mp.upload_part_from_file(fp, part_num=i + 1, is_last_part=last)

    mp.complete_upload()




#### 注意事项
* 对于使用加密模式上传的数据，请使用加密模式下（local_encrypt=True）的get方法进行下载。未设置加密模式的get下载下来的这份数据是加密的，无法解读。
* 加密上传默认进行MD5验证，以防止网络传输过程中的数据损坏。在文件较大的情况下，对加密后文件的MD5计算较为耗时（每500MB约耗时10s），如果不能接受这种额外耗时，可以在调用方法时设置calc_md5=False来关闭MD5校验功能。当然，我们不推荐您关闭MD5校验。

```
#PUT上传取消MD5 CHECK：
ret = kw.set_contents_from_string(test_str, calc_encrypt_md5=False)
ret = kw.set_contents_from_filename(test_path, calc_encrypt_md5=False)
#分块上传时取消MD5 CHECK：
mp = b.initiate_multipart_upload(os.path.basename(path), calc_encrypt_md5=False)
```
* 用户key的MD5值将作为自定义header放入元数据，方便您后续可能的验证操作。对key的MD5计算方法如下：

```
import hashlib
import base64
md5_generator = hashlib.md5()
md5_generator.update("YOUR_KEY".encode())
print(base64.b64encode(md5_generator.hexdigest().encode()))
```
* 如果需要在分块上传相关代码中加入重试逻辑，请将开始重试的part_num后的所有块都进行重试。比如上传8块，从第5块开始重试，则需要重新上传的块为5、6、7、8。
* 对于空文件/空字符串的put请求，即使设置了加密模式也不会加密。