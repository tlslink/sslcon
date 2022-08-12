https://gitlab.com/openconnect/ocserv/-/blob/master/src/worker-http.c#L150

https://github.com/openconnect/openconnect/blob/master/gnutls-dtls.c#L75

https://www.rfc-editor.org/rfc/rfc5288.html

https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-4

worker-http.c 的
dtls_ciphersuite_st [ciphersuites12](https://gitlab.com/openconnect/ocserv/-/blob/master/src/worker-http.c#L150)
仅支持两种，AES128-GCM-SHA256 和 AES256-GCM-SHA384，其中 AES128-GCM-SHA256 返回的 ID 为 0x009c，因此判断为

0x00,0x9C TLS_RSA_WITH_AES_128_GCM_SHA256
