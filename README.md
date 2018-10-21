# Apache Warden module

this module enables Warden: a server-side proxy which automatically enforces intra-scope sub-session linking on incoming HTTP(S) requests.

Warden aims at improving protection against sub-session hijacking without requiring changes to the server-side logic of the website to protect.

You can find more about Warden in [Sub-session hijacking on the Web: root causes and prevention](http://www.dais.unive.it/~calzavara/papers/jcs18.pdf) by Stefano Calzavara, Alvise Rabitti and Michele Bugliesi, published in Journal of Computer Security (JCS), 2018.

## configuration

### login path

variable `WARDEN_LOGIN_PATH` must be set to contain the path part of the login URL

### session cookies

session cookies must be configured directly in the source code at the moment:

* `WARDEN_SESSION_COOKIES_NUM` (line 29) must be set to the total number of session cookies that will be tracked 
* update the cookies names under the `/* configure session cookies names here */` line, duplicating/deleting lines if needed 
* `WARDEN_SCOPES_NUM` (line 30) must be set to the total number of scopes that need to be tracked 
* update cookies scopes in lines under the `/* configure session cookies scopes here */` line, duplicating/deleting lines if needed

### server key

update the server HMAC key with some fresh value in the variable `wdn->hmac_key` near the `// select a unique hmac key (this never leaves the server)` line, and the initialization vector in `wdn->iv`

### apache files

the /etc/apache2/mods-available/warden.load file needs to be (you can find an example in the repo):
```
LoadModule warden_module      /usr/lib/apache2/modules/mod_warden.so
```

the /etc/apache2/mods-available/warden.conf needs to be (you may need to create it):
```
<IfModule mod_warden.c>
        AddHandler wdn-register-handler .wdn
        SetOutputFilter WARDENOUT
</IfModule>
```

### persistent storage

Warden uses Apache DBD for persistent storage, actually configured to use an sqlite3 db.
The DBD backend can be configured changing the value of the `WARDEN_DB_TYPE` value.
The path to the sqlite3 db can be configured with the `WARDEN_DB_PARAMS` value.
The sqlite3 file must be initialized with:
```
sqlite3 /path/to/warden.db
CREATE TABLE keystore (key,scope,num, UNIQUE(key,scope) ON CONFLICT REPLACE);
```

### Other configurable values

* `WARDEN_KEY_COOKIE_NAME` holds the name of the cookie used for the session key, change it if you alrady have cookies with the same name (if concerned: see Warden description in the paper to understand why it doesn't need particular protection)
* `WARDEN_AUTH_COOKIE_NAME` holds the name used for linker cookies, change it if conflicts arise, but it's quite difficult it happens
* `WARDEN_SHADOW_POSTFIX` holds a postfix appended to the name of session cookies, change it if you happen to have cookies with the same structure and postfix
* `WARDEN_STATIC_HOST_NAME` put the static hostname here, but frankly this should be made dynamic ;)

## compilation

### dependencies

Warden needs apache2 developer tools, libssl and its development headers installed, it has been tested with ubuntu package version 1.0.2g, but it would probably work on earlier versions too.

### compiling

Warden can be compiled with
```
apxs -i -a -c mod_warden.c
```

you can then restart apache and Warden will be active.