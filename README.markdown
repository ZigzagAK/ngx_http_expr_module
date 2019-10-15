Name
====

ngx_http_expr_module - lazy computed complex variables.

Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Synopsis](#synopsis)
* [Description](#description)
* [Configuration directives](#configuration-directives)

Status
======

This library is production ready.

Description
===========

Module makes possible declare complex variables with lazy computation. This is may be used to choose access_log format dynamically.

[Back to TOC](#table-of-contents)

Synopsis
========

```nginx
http {
    log_format  main  $format;

    access_log  logs/access.log  main;

    expr_max_hash_size 10240;

    server {
        listen 4444;

        location /test1 {
            expr $format '1111 $remote_addr - $remote_user [$time_local] "$request" $status $request_time $upstream_addr';
            return 200 test1;
        }

        location /test2 {
            expr $format '2222 $remote_addr - $remote_user [$time_local] "$request" $status $request_time $upstream_addr';
            return 200 test2;
        }

        location /test3 {
            expr $format '3333 $remote_addr - $remote_user [$time_local] "$request" $status $request_time $upstream_addr';
            echo_exec @inner1;
        }

        location @inner1 {
            echo_exec @inner2;
        }

        location @inner2 {
            return 200 $uri;
        }
    }
}
```

[Back to TOC](#table-of-contents)

Configuration directives
========================

expr
----
* **syntax**: `expr $var <complex value>`
* **context**: `location`

Declare complex variable with lazy computation.

Directive is not support inheritance.

[Back to TOC](#table-of-contents)

expr_max_hash_size
------------------
* **syntax**: `expr $var <complex value>`
* **default**: 1024
* **minimum**: 256
* **context**: `http,server,location`

Maximum number of locations per variable.

[Back to TOC](#table-of-contents)
