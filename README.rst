libvmod-ldap_mcna
=================

This repository contains a varnish module that is used to authenticate
users against an LDAP server.  I wrote it because the libvmod-ldap
module (https://github.com/xcir/libvmod-ldap) did not work for me and
I found fixing it too troublesome.  libvmod-ldap_mcna is written
mostly in C++, which I find easier to deal with than C.  It is
tailored around how we use the LDAP server and will propably need some
tweaking if it is to be used with some other server.

The module caches authentication information so that not every request
results in a request to the LDAP server.  Cache entries expire after
five seconds, this should probably be made configurable.

Usage::

  import ldap;
  
  backend default {
    .host = "127.0.0.1";
    .port = "2012";
  }
  
  sub vcl_init {
          ldap.make_realm("my-company",
                          "ldap://my-ldap-server.company.com:389",
                          "cn=Directory Manager",
                          "the-secret-password",
                          "ou=Users,dc=company,dc=com",
                          "uid=%s");
  }
  
  sub vcl_error {
          if (obj.status == 401) {
                  set obj.http.WWW-Authenticate = {"Basic realm="Authorization Required""};
                  synthetic {"Error 401 Unauthorized"};
                  return(deliver);
          }
  }
  
  sub vcl_recv {
          if (!ldap.basic_auth("my-company", req.http.Authorization)) {
                  error 401;
          }
  }
