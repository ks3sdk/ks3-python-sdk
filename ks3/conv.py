try:
    import urllib.parse as parse  # for Python 3
    import urllib.request as request
    import urllib.error as error
except ImportError:
    import urllib as parse  # for Python 2
    import urllib as request
    import urllib as error

def fun(bucketname, url="http://10.4.22.2:9911/console"):
    para = parse.urlencode({"bucketname": bucketname})
    path = url + "?%s" % para
    resp = request.urlopen(path)
    return resp.read()

if __name__ == '__main__':
    fun("sdktest123")
