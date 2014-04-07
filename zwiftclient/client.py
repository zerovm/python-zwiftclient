import warnings
from swiftclient import http_connection, quote, LengthWrapper, http_log, \
    store_response, ClientException, Connection


class ZwiftConnection(Connection):

    def exec_account(self, container, obj, contents, content_length=None,
                     etag=None, chunk_size=None, content_type=None,
                     headers=None, query_string=None, response_dict=None):
        """Wrapper for :func:`exec_account`"""

        def _default_reset(*args, **kwargs):
            raise ClientException('exec_account(%r, %r, ...) failure and no '
                                  'ability to reset contents for resubmit.'
                                  % (container, obj))

        if isinstance(contents, str) or not contents:
            # if its a str or None then you can retry as much as you want
            reset_func = None
        else:
            reset_func = _default_reset
            if self.retries > 0:
                tell = getattr(contents, 'tell', None)
                seek = getattr(contents, 'seek', None)
                if tell and seek:
                    orig_pos = tell()
                    reset_func = lambda *a, **k: seek(orig_pos)

        return self._retry(reset_func, exec_account, container, obj, contents,
                           content_length=content_length, etag=etag,
                           chunk_size=chunk_size, content_type=content_type,
                           headers=headers, query_string=query_string,
                           response_dict=response_dict)


def exec_account(url, token=None, container=None, name=None, contents=None,
                 content_length=None, etag=None, chunk_size=None,
                 content_type=None, headers=None, http_conn=None, proxy=None,
                 query_string=None, response_dict=None):
    """
    Execute a job

    :param url: storage URL
    :param token: auth token; if None, no token will be sent
    :param container: container name that the object is in; if None, the
                      container name is expected to be part of the url
    :param name: object name to put; if None, the object name is expected to be
                 part of the url
    :param contents: a string or a file like object to read object data from;
                     if None, a zero-byte put will be done
    :param content_length: value to send as content-length header; also limits
                           the amount read from contents; if None, it will be
                           computed via the contents or chunked transfer
                           encoding will be used
    :param etag: etag of contents; if None, no etag will be sent
    :param chunk_size: chunk size of data to write; it defaults to 65536;
                       used only if the the contents object has a 'read'
                       method, eg. file-like objects, ignored otherwise
    :param content_type: value to send as content-type header; if None, no
                         content-type will be set (remote end will likely try
                         to auto-detect it)
    :param headers: additional headers to include in the request, if any
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
    :param proxy: proxy to connect through, if any; None by default; str of the
                  format 'http://127.0.0.1:8888' to set one
    :param query_string: if set will be appended with '?' to generated path
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :returns: (headers, body) tuple
    :raises ClientException: HTTP POST request failed
    """
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url, proxy=proxy)
    path = parsed.path
    if container:
        path = '%s/%s' % (path.rstrip('/'), quote(container))
    if name:
        path = '%s/%s' % (path.rstrip('/'), quote(name))
    if query_string:
        path += '?' + query_string
    if headers:
        headers = dict(headers)
    else:
        headers = {}
    if token:
        headers['X-Auth-Token'] = token
    if etag:
        headers['ETag'] = etag.strip('"')
    if content_length is not None:
        headers['Content-Length'] = str(content_length)
    else:
        for n, v in headers.items():
            if n.lower() == 'content-length':
                content_length = int(v)
    if content_type is not None:
        headers['Content-Type'] = content_type
    if not contents:
        headers['Content-Length'] = '0'
    headers['X-Zerovm-Execute'] = '1.0'
    if hasattr(contents, 'read'):
        if chunk_size is None:
            chunk_size = 65536
        if content_length is None:
            def chunk_reader():
                while True:
                    data = contents.read(chunk_size)
                    if not data:
                        break
                    yield data
            conn.request('POST', path, data=chunk_reader(), headers=headers)
        else:
            # Fixes https://github.com/kennethreitz/requests/issues/1648
            data = LengthWrapper(contents, content_length)
            conn.request('POST', path, data=data, headers=headers)
    else:
        if chunk_size is not None:
            warn_msg = '%s object has no \"read\" method, ignoring chunk_size'\
                % type(contents).__name__
            warnings.warn(warn_msg, stacklevel=2)
        conn.request('POST', path, contents, headers)
    resp = conn.getresponse()
    body = resp.read()
    headers = {'X-Auth-Token': token}
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), 'POST',),
             {'headers': headers}, resp, body)

    store_response(resp, response_dict)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException('Object PUT failed', http_scheme=parsed.scheme,
                              http_host=conn.host, http_path=path,
                              http_status=resp.status, http_reason=resp.reason,
                              http_response_content=body)
    return body, dict(resp.getheaders())
