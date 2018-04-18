# KS3 SDK for python使用指南
---

## 开发前准备
### 安装依赖模块

	pip install six


### 安装python sdk
#### 在线安装

	pip install ks3sdk
	
#### 本地安装
1、通过git下载SDK到本地

	git clone https://github.com/ks3sdk/ks3-python-sdk.git


2、进入ks3-python-sdk目录

	cd ks3-python-sdk

3、安装SDK

	python setup.py install

### 初始化connection

    from ks3.connection import Connection
    ak = 'YOUR_ACCESS_KEY'
    sk = 'YOUR_SECRET_KEY'
    c = Connection(ak, sk, host='YOUR_REGION_ENDPOINT', is_secure=False, domain_mode=False)

*常用参数说明*

+ ak：金山云提供的ACCESS KEY ID
+ sk：金山云提供的SECRET KEY ID
+ host：金山云提供的各个Region的域名（例 ks3-cn-beijing.ksyun.com）,具体定义可参考 [API接口文档-Region(区域)](https://docs.ksyun.com/read/latest/65/_book/index.html)
+ is_secure：是否通过HTTPS协议访问Ks3，True:启用  False:关闭
+ domain_mode：是否使用自定义域名访问Ks3（host填写自定义域名），True:是 False:否

### 运行环境
适用于2.6、2.7的Python版本

## SDK介绍及使用
### 资源管理操作
* [List Buckets](#list-buckets) 列出客户所有的Bucket信息
* [Create Bucket](#create-bucket) 创建一个新的Bucket
* [Delete Bucket](#delete-bucket) 删除指定Bucket
* [Get Bucket ACL](#get-bucket-acl) 获取Bucket的ACL
* [Put Bucket ACL](#put-bucket-acl) 设置Bucket的ACL
* [Head Object](#head-object) 获取Object元信息
* [Get Object](#get-object) 下载Object数据
* [Put Object](#put-object) 上传Object数据
* [Put Object Copy](#put-object-copy) 复制Object数据
* [Delete Object](#delete-object) 删除Object数据
* [List Objects](#list-objects) 列举Bucket内的Object
* [Get Object ACL](#get-object-acl) 获得Bucket的acl
* [Put Object ACL](#put-object-acl) 上传object的acl
* [Upload Part](#upload-part) 上传分块
* [Generate URL](#generate-url) 生成下载外链

### Service操作

#### List Buckets：

*列出客户所有的 Bucket 信息*

    buckets = c.get_all_buckets()
    for b in buckets:
        print b.name

### Bucket操作

#### Create Bucket： 

*创建一个新的Bucket*

在建立了连接后，可以创建一个bucket。bucket在s3中是一个用于储存key/value的容器。用户可以将所有的数据存储在一个bucket里，也可以为不同种类数据创建相应的bucket。

    bucket_name = "YOUR_BUCKET_NAME"
    b = c.create_bucket(bucket_name)

注：这里如果出现409 conflict错误，说明请求的bucket name有冲突，因为bucket name是全局唯一的

#### Delete Bucket:

*删除指定Bucket*

删除一个bucket可以通过delete_bucket方法实现。

    c.delete_bucket(bucket_name)

如果bucket下面存在key，那么需要首先删除所有key

    b = c.get_bucket(bucket_name)
    for k in b.list():
        k.delete()
    c.delete_bucket(bucket_name)

#### Get Bucket ACL:

*获取Bucket的ACL*

    acp = b.get_acl()
    >>> acp
    <Policy: MTM1OTk4ODE= (owner) = FULL_CONTROL>
    >>> acp.acl
    <ks3.acl.ACL object at 0x23cf750>
    >>> acp.acl.grants
    [<ks3.acl.Grant object at 0xf63810>]
    >>> for grant in acp.acl.grants:
    ...   print grant.permission, grant.display_name, grant.email_address, grant.id
    ...

#### Put Bucket ACL:

*设置Bucket的ACL*
  
    #设置bucket的权限, private or public-read or public-read-write
    b.set_acl("public-read")

### Object操作

#### Head Object:
*获取Object元信息*

获取Object元数据信息（大小、最后更新时间等）

	from ks3.connection import Connection
	
	bucket_name = "YOUR_BUCKET_NAME"
	key_name = "YOUR_KEY_NAME"
	b = c.get_bucket(bucket_name)
	try:
	    k = b.get_key(key_name)
	    if k:
	    	print k.name, k.size, k.last_modified
	    	#print k.__dict__
	except:
		pass # 异常处理

#### Get Object：
*下载该Object数据*
 
下载object，并且作为字符串返回

    from ks3.connection import Connection
     
    bucket_name = "YOUR_BUCKET_NAME"
    key_name = "YOUR_KEY_NAME"
    b = c.get_bucket(bucket_name)
    try:
	    k = b.get_key(key_name)
	    s = k.get_contents_as_string()
		print s
    except:
	    pass # 异常处理

下载object，并且保存到文件中

	#保存到文件
	k.get_contents_to_filename("/tmp/KS3SDK_download_test")
	#保存到文件句柄
	f=open("/tmp/test_file","rb")
	k.set_contents_from_file(f)

#### Put Object
*上传Object数据* 

将指定目录的文件上传，同时可以指定文件ACL

    bucket_name = "YOUR_BUCKET_NAME"
    key_name = "YOUR_KEY_NAME"
    try: 
	    b = c.get_bucket(bucket_name)
	    k = b.new_key(key_name)
	    #object policy : 'private' or 'public-read'
	    ret=k.set_contents_from_filename("/root/KS3SDK_upload_test", policy="private")
	    if ret and ret.status == 200:
	    	print "上传成功"
	 except:
	 	pass #异常处理   

将字符串所谓value上传

    k.set_contents_from_string('This is a test of S3')
    
#### Put Object Copy
*复制Object数据* 

将指定Bucket下的文件复制到本Bucket下（需要对源Bucket下的文件具有读权限）

    bucket_name = "YOUR_DST_BUCKET_NAME"
    key_name = "YOUR_DST_KEY_NAME"
    try: 
	    b = c.get_bucket(bucket_name)
	    b.copy_key(key_name,"YOUR_SRC_BUCKET_NAME","YOUR_SRC_KEY_NAME")
	 except:
	 	pass #异常处理
        
#### Delete Object
*删除Object数据*

	try: 
		b=conn.get_bucket(YOUR_BUCKET_NAME)
		b.delete_key(YOUR_KEY_NAME)
	except:
 		pass #异常处理   
	
#### List Objects
*列举Bucket内的文件或者目录*

	from ks3.prefix import Prefix
	from ks3.key import Key
	
	b = c.get_bucket(bucket_name)
	keys = b.list(delimiter='/')
	for k in keys:
	    if isinstance(k,Key):
	        print 'file:%s' % k.name
	    elif isinstance(k,Prefix):
	        print 'dir:%s' % k.name

*列举Bucket内指定前缀的文件*

    keys = b.list(prefix="PREFIX")

#### Get Object ACL
*获得Object的acl*

    b = c.get_bucket(bucket_name)
    policy = b.get_acl(key_name)
    print policy.to_xml()

#### Put Object ACL

	#object policy : 'private' or 'public-read'
	b.set_acl("public-read", test_key)

#### Upload Part：
*分块上传*

如果你想上传一个大文件，你可以将它分成几个小份，逐个上传，s3会按照顺序把它们合成一个最终的object。整个过程需要几步来完成，下面的demo程序是通过python的FileChunkIO模块来实现的。所以可能需要首先运行pip install FileChunkIO来安装。

    >>> import math, os
    >>> from ks3.connection import Connection
    >>> from filechunkio import FileChunkIO
     
    # Connect to S3
    >>> bucket_name = "YOUR_BUCKET_NAME"
    >>> c = Connection(ak, sk)
    >>> b = c.get_bucket(bucket_name)
     
    # Get file info
    >>> source_path = 'path/to/your/file.ext'
    >>> source_size = os.stat(source_path).st_size
     
    # Create a multipart upload request
    >>> mp = b.initiate_multipart_upload(os.path.basename(source_path))
     
    # Use a chunk size of 50 MiB (feel free to change this)
    >>> chunk_size = 52428800
    >>> chunk_count = int(math.ceil(source_size / chunk_size))
     
    # Send the file parts, using FileChunkIO to create a file-like object
    # that points to a certain byte range within the original file. We
    # set bytes to never exceed the original file size.
    >>> for i in range(chunk_count + 1):
    >>>     offset = chunk_size * i
    >>>     bytes = min(chunk_size, source_size - offset)
    >>>     with FileChunkIO(source_path, 'r', offset=offset,
                             bytes=bytes) as fp:
    >>>         mp.upload_part_from_file(fp, part_num=i + 1)
     
    # Finish the upload
    >>> mp.complete_upload()
    
*获取已上传分块列表*

	bucket = conn.get_bucket(bucket_name)
	for p in bucket.list_multipart_uploads():
		print 'uploadId:%s,key:%s' % (p.id, p.key_name)
		for i in p:
			print i.part_number, i.size, i.etag, i.last_modified

#### Generate URL
*生成下载外链地址*

对私密属性的文件生成下载外链（该链接具有时效性）

    b = conn.get_bucket(bucket_name)
    k = b.get_key(obj_key)
    if k:
	    url = k.generate_url(60) # 60s 后该链接过期
	    print url

指定时间过期
	
	k.generate_url(1492073594,expires_in_absolute=True) # 1492073594为Unix Time

<br />

## 客户端文件加密
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
对put、get方法加密客户端和普通客户端用法基本一致，不同之处在于初始化Connection对象时需要多填两个参数。

    c = Connection(ak, sk, host,is_secure=False, domain_mode=False, local_encrypt=True, local_key_path="your_key_path")
    b = c.get_bucket("your_bucket")
    #put
    kw = b.new_key("your_key")
    ret = kw.set_contents_from_string("some string")
    #get
    get_key = b.get_key("your_key")
    s = get_key.get_contents_as_string()
    print "Result:" + s

#### 分块上传
*加密客户端的分块上传不支持对文件的并行上传！分块上传时必须依次序上传每一块，否则数据将无法解密。*<br />
示例1：使用FileChunkIO进行分块上传。与普通客户端的方法基本一致，和put一样只需在初始化时增加参数。

    c = Connection(ak, sk, host,is_secure=False, domain_mode=False, local_encrypt=True, local_key_path="your_key_path")
    #继续普通分块上传方法

示例2：自己切分文件进行分块上传。除了修改Connection的参数之外，还需在调用upload_part_from_file方法时指定is_last_part的值。

    c = Connection(ak, sk, host,is_secure=False, domain_mode=False, local_encrypt=True, local_key_path="your_key_path")
    b = c.get_bucket("your_bucket")
    mp = b.initiate_multipart_upload("your_file")
    fp = open('part1','rb')
    mp.upload_part_from_file(fp,part_num=1,is_last_part=False)
    fp.close()
    fp = open('part2','rb')
    mp.upload_part_from_file(fp,part_num=2,is_last_part=True)
    fp.close()
    result = mp.complete_upload()




#### 注意事项
* 对于使用加密模式上传的数据，请使用加密模式下（local_encrypt=True）的get方法进行下载。未设置加密模式的get下载下来的这份数据是加密的，无法解读。
* 加密上传默认进行MD5验证，以防止网络传输过程中的数据损坏。在文件较大的情况下，对加密后文件的MD5计算较为耗时（每500MB约耗时10s），如果不能接受这种额外耗时，可以在调用方法时设置calc_md5=False来关闭MD5校验功能。当然，我们不推荐您关闭MD5校验。

```
#PUT时取消MD5 CHECK：
ret = kw.set_contents_from_string(test_str, calc_encrypt_md5=False)
ret = kw.set_contents_from_filename(test_path, calc_encrypt_md5=False)
#分块时取消MD5 CHECK：
mp = b.initiate_multipart_upload(os.path.basename(path), calc_encrypt_md5=False)
```
* 用户key的MD5值将作为自定义header放入元数据，方便您后续可能的验证操作。对key的MD5计算方法如下：

```
import hashlib
import base64
md5_generator = hashlib.md5()
md5_generator.update("your_key")
base64.b64encode(md5_generator.hexdigest())
```
* 如果需要在分块上传相关代码中加入重试逻辑，请将开始重试的part_num后的所有块都进行重试。比如上传8块，从第5块开始重试，则需要重新上传的块为5、6、7、8。
* 对于空文件/空字符串的put请求，即使设置了加密模式也不会加密。