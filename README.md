# Apache Warden module

this module enables Warden: a server-side proxy which automatically enforces intra-scope sub-session linking on incoming HTTP(S) requests.

Warden aims at improving protection against sub-session hijacking without requiring changes to the server-side logic of the website to protect.

You can find more about Warden at: ************

## configuration

### login path

variable `WARDEN_LOGIN_PATH` must be set to contain the path part of the login URL

### session cookies

session cookies must be configured directly in the source code at the moment:

* `WARDEN_SESSION_COOKIES_NUM` must be set to the total number of session cookies that will be tracked 
* update the cookies names near line 340, duplicating/deleting lines if needed 
* update cookies scopes in the subsequent lines, duplicating/deleting lines if needed

### server key

update the server HMAC key with some fresh value in the variable `wdn->hmac_key` near line 330, and the initialization vector in `wdn->iv`

### apache files

the /etc/apache2/mods-available/warden.load file needs to be:
```
LoadModule warden_module      /usr/lib/apache2/modules/mod_warden.so
```

the /etc/apache2/mods-available/warden.conf needs to be:

```
<IfModule mod_warden.c>
        AddHandler wdn-register-handler .wdn
        SetOutputFilter WARDENOUT
</IfModule>
```

### persistent storage

Warden uses Apache DBD for persistent storage, presently configured to use an sqlite3 db.
The DBD backend can be configured changing the value of the `WARDEN_DB_TYPE` value.
The path to the sqlite3 db can be configured with the `WARDEN_DB_PARAMS` value.
The sqlite3 file must be initialized with:
```
sqlite3 /path/to/warden.db
CREATE TABLE keystore (key,scope,num, UNIQUE(key,scope) ON CONFLICT REPLACE);
```

### Other configurable values

* `WARDEN_KEY_COOKIE_NAME` holds the name of the cookie used for the session key, change it if you alrady have cookies with the same name (if concerned: see Warden description to understand why it doesn't need particular protection)
* `WARDEN_AUTH_COOKIE_NAME` holds the name used for linker cookies, change it if conflicts arise, but it's quite difficult it happens
* `WARDEN_SHADOW_POSTFIX` holds a postfix appended to the name of session cookies, change it if you happen to have cookies with the same structure and postfix
* `WARDEN_STATIC_HOST_NAME` put the static hostname here, but frankly this should be made dynamic ;)

## compilation

### dependencies

Warden needs some libssl and its development headers installed, it has been tested with ubuntu package version 1.0.2g, but it would probably work on earlier versions too.

### compiling

Warden can be compiled with
```
apxs -i -a -c mod_warden.c
```
after compiling pay attention to the config files for apache, as warden.load seems to be rewritten after each compiler run.
you can the restart apache