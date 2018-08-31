#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <util_cookies.h>
#include <apr.h>
#include <apr_tables.h>
#include <apr_strings.h>
#include <apr_base64.h>
#include <apr_pools.h>
#include <apr_dbd.h>
#include <apr_escape.h>
#include <http_log.h>
#include </usr/include/openssl/hmac.h>
#include </usr/include/openssl/evp.h>
#include </usr/include/openssl/aes.h>
#include </usr/include/openssl/rand.h>

#define WARDEN_DB_TYPE  "sqlite3"
#define WARDEN_DB_PARAMS  "/var/www/html/warden/warden.db"

// path to the login page
#define WARDEN_LOGIN_PATH "/disney/login.php"

// the number of session cookies, names are to be set near the end of wdn_srv_config function
#define WARDEN_SESSION_COOKIES_NUM 3
#define WARDEN_SCOPES_NUM 1
#define WARDEN_AUTH_COOKIE_NAME "warden_linker"
#define WARDEN_KEY_COOKIE_NAME "warden_key"
#define WARDEN_SHADOW_POSTFIX "_shadow"
#define WARDEN_KEY_LENGTH 256

// the hostname warden is protecting, it could probably be dynamically set at startup
// but it's a bit of a mess when doing local tests on localhost accessed from outside
// this actually saves some apache config time
#define WARDEN_STATIC_HOST_NAME "rabitti.dais.unive.it"

typedef struct {
    char prot;      // H = http, S = https, * = *
    char host[256]; // FIXME fixed length
    char path[256]; // FIXME fixed length
} cookiescope;

typedef struct {
    char *name;
    char *value;
    char *domain;
    char *path;
    bool secure;
    bool http_only;
} cookie;

typedef struct {
    cookiescope             scope;
    char                    *name;
} binding;

/*
    server data used to store persistent information of the module
*/

typedef struct
{
    const apr_dbd_driver_t  *db_driver;         // driver for db connection
    apr_dbd_t               *db_handle;         // handle of db connection
    const char              *db_error;          // error (if any) during db init
    
    // room for prepared queries
    apr_dbd_prepared_t      *db_new_keyscope;
    apr_dbd_prepared_t      *db_get_keyscope_counter;
    apr_dbd_prepared_t      *db_inc_keyscope_counter;
    apr_dbd_prepared_t      *db_del_key;

    apr_pool_t              *pool;              // own memory pool
    unsigned char           *hmac_key;
    unsigned char           *iv;
    unsigned char           *aad;

    char                    *login_URL;
    char                    *expected_session_cookies[WARDEN_SESSION_COOKIES_NUM];
    cookiescope             cookie_scopes[WARDEN_SCOPES_NUM];
} wdn_srv_data;

/* prototypes of our functions in this module */
static void         register_hooks(apr_pool_t *pool);
static void *       wdn_srv_config(apr_pool_t *pchild, server_rec *s);

// main hooks
static int          wdn_response_filter(ap_filter_t *f, apr_bucket_brigade *pbbIn);
static apr_status_t wdn_request_filter(request_rec *r);

// Cookie helpers 
static cookie       wdn_bake_cookie(request_rec *r, char *cookie_string, const char *base_domain);
static cookiescope  wdn_get_cookie_scope(cookie ck);
static bool         is_cookie_in_jar(request_rec *r, char *jar, char *cookie_name);
static char *       get_cookiestring_from_jar(request_rec *r, char * jar, char *cookie_name);
static char *       wdn_extract_domain(request_rec *r,char *uri);
static bool         wdn_is_dotted_suffix(char *test, char *against);
static bool         is_cookie_scope_leq(request_rec *r, cookiescope test_this, cookiescope test_against);
static void         strip_cookies_from_request(request_rec *r, char **cklist);

// other helpers 
static void         debug_this_jar(request_rec *r, char *jarname,cookie jar[WARDEN_SESSION_COOKIES_NUM]);
static char *       rtrim(char* string, char junk);
static char *       calculate_base64_hmac(request_rec *r,const char *data, int data_len, unsigned char* key, int key_len);
static bool         extract_sessioncookies_from_request(request_rec *r, char **sc, cookie *res);
static bool         extract_sessioncookies_from_response(request_rec *r, char **sc, cookie *res);
static char *       scope_to_string(request_rec *r, cookiescope s);
static cookiescope  make_cookie_scope(request_rec *r,char pr, const char *hs, char *pt);

static char *       setup_session(request_rec *r);
static unsigned char *generate_session_key(request_rec *r);
static bool         are_we_in_session(request_rec *r, wdn_srv_data *wdn);

static void         increase_scope_ID(request_rec *r, char *session_key, int i);
unsigned char *     get_KS_from_request(request_rec *r);

static char *       encrypt_and_b64_for_cookie_payload(request_rec *r, unsigned char *plaintext, int plaintext_len, unsigned char *key);
static char *       unb64_and_decrypt_from_cookie_payload(request_rec *r, const char *payload, unsigned char *key);
static char *       get_current_KS_scope_ID(request_rec *r, char *key, cookiescope scope);
static bool         is_linking_cookie_valid(request_rec *r, const char *cookie_hmac, char *plain_to_hmac, cookiescope scope, unsigned char *key);

/* AES STUFF */
void handleErrors(void)
{

}

int aesencrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
            int aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(aad && aad_len > 0) {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(plaintext) {
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();

        ciphertext_len = len;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aesdecrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
            int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(aad && aad_len > 0) {
        if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(ciphertext) {
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();

        plaintext_len = len;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}
/* END AES */

char* rtrim(char* string, char junk) {
    char* original = string + strlen(string);
    while(*--original == junk);
    *(original + 1) = '\0';
    return string;
}

/* Define our module as an entity and assign a function for registering hooks  */

module AP_MODULE_DECLARE_DATA   warden_module =
{ 
    STANDARD20_MODULE_STUFF,
    NULL,                   /* Per-directory configuration handler */
    NULL,                   /* Merge handler for per-directory configurations */
    wdn_srv_config,         /* Per-server configuration handler */
    NULL,                   /* Merge handler for per-server configurations */
    NULL,                   /* Any directives we may have for httpd */
    register_hooks          /* Our hook registering function */
};

/*
    wdn_srv_config
    sets up all the useful data like prepared DB queries, session cookies, and session cookies scopes

    WARN: session cookies and session cookies scopes MUST BE configured here
*/

static void *wdn_srv_config(apr_pool_t *pchild, server_rec *s) {
    apr_status_t    res;
    cookiescope     cs;

    /* allocates the wdn_srv_data object in memory so that it will be possible to retrieve it by the child init */
    wdn_srv_data *wdn = apr_pcalloc(pchild,sizeof(*wdn));

    // DB
    res = apr_pool_create(&wdn->pool, pchild);
    if (res != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, res, s->process->pool, "[init] Failed to create subpool for warden");
    }

    res = apr_dbd_init(wdn->pool);
    if (res != APR_SUCCESS)
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, s, "[init] problem initializing db pool");

    res = apr_dbd_get_driver(wdn->pool,WARDEN_DB_TYPE,&wdn->db_driver);
    if (res != APR_SUCCESS)
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, s, "[init] problem getting db driver");

    res = apr_dbd_open_ex(wdn->db_driver,wdn->pool,WARDEN_DB_PARAMS,&wdn->db_handle,&wdn->db_error);
    if (res != APR_SUCCESS)
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, s, "[init] problem opening db connection, error: %s",wdn->db_error);

    // INSERT A NEW KEY/SCOPE RECORD
    res = apr_dbd_prepare(wdn->db_driver,wdn->pool,wdn->db_handle,"INSERT INTO keystore (key,scope,num) VALUES (%s,%s,0)","insert a new key/scope record",&wdn->db_new_keyscope);
    // GET A KEY/SCOPE RECORD COUNTER
    res = apr_dbd_prepare(wdn->db_driver,wdn->pool,wdn->db_handle,"SELECT num FROM keystore WHERE key=%s AND scope=%s","gets the counter of a key/scope record",&wdn->db_get_keyscope_counter);
    // ADD 1 TO A KEY/SCOPE RECORD
    res = apr_dbd_prepare(wdn->db_driver,wdn->pool,wdn->db_handle,"UPDATE keystore SET num=num+1 WHERE key=%s AND scope=%s","changes the counter of a key/scope record",&wdn->db_inc_keyscope_counter);
    // DELETE ALL THE RECORDS BOUND TO A KEY
    res = apr_dbd_prepare(wdn->db_driver,wdn->pool,wdn->db_handle,"DELETE FROM keystore WHERE key=%s","delete all the key/scope records with a certain key",&wdn->db_del_key);

    ap_log_perror(APLOG_MARK, APLOG_CRIT, res, s->process->pool, "[init] DB stuff correctly set up for %s", WARDEN_DB_TYPE);

    /* CONFIGURE STUFF HERE */
    // CRYPTO
    // select a unique hmac key (this never leaves the server)
    wdn->hmac_key = apr_pstrdup(wdn->pool,"thisIStheSERVERkey.ThisNeverLeavesTheServer");
    wdn->iv  = apr_pstrdup(wdn->pool,"0123456789012345");
    wdn->aad = apr_pstrdup(wdn->pool,"");

    // login URL has to be configured in the #define section
    wdn->login_URL  = apr_pstrdup(wdn->pool,WARDEN_LOGIN_PATH);
    
    // repeat the following lines as much as needed up to WARDEN_SESSION_COOKIES_NUM and update
    // it with the correct index and the session cookie names
    // wdn->expected_session_cookies[0]    = apr_pstrdup(wdn->pool,"session_cookie_1");
    // wdn->expected_session_cookies[1]    = apr_pstrdup(wdn->pool,"session_cookie_2");
    wdn->expected_session_cookies[0]    = apr_pstrdup(wdn->pool,"identity");
    wdn->expected_session_cookies[1]    = apr_pstrdup(wdn->pool,"partner");
    wdn->expected_session_cookies[2]    = apr_pstrdup(wdn->pool,"town");
    // wdn->expected_session_cookies[1]    = apr_pstrdup(wdn->pool,"wordpress_1e6110aa4c2980eedcf79a181d236f56");

    // UGLY way to build session cookies scopes ;)
    cs.prot = '*';
    strcpy(cs.host,apr_pstrdup(wdn->pool,WARDEN_STATIC_HOST_NAME));
    strcpy(cs.path,apr_pstrdup(wdn->pool,"/"));
    wdn->cookie_scopes[0] = cs;
    
    // cs.prot = 'S';
    // cs.prot = '*';
    // host and path are the same as the previous scope, so we keep them
    // wdn->cookie_scopes[1] = cs;


    ap_log_perror(APLOG_MARK, APLOG_CRIT, res, s->process->pool, "[init] Setup OK");

    return wdn;
}

static void register_hooks(apr_pool_t *pool)
{
    ap_register_output_filter("WARDENOUT", wdn_response_filter, NULL, AP_FTYPE_RESOURCE);
    ap_hook_post_read_request(wdn_request_filter, NULL, NULL, APR_HOOK_FIRST);
}

/*
    are_we_in_session
    parses the cookies passed with request r looking for the presence of session cookies
    AND the absence of corresponding shadow cookies
    If we have any session cookie without a correponding shadow cookie returns TRUE, otherwise FALSE

    This function is used in contexts where being in session triggers more checks, done by code
    after this function's return

    FIXME: at the moment we check for the validity of found shadow cookies, but we don't take any
    action based upon this
*/

static bool are_we_in_session(request_rec *r, wdn_srv_data *wdn) {
    int i;
    const char *ckval;
    const char *swval;
    bool in_session = false;

    for (i=0;i<WARDEN_SESSION_COOKIES_NUM;i++) {
        ap_cookie_read(r,wdn->expected_session_cookies[i],&ckval,false);
        
        if (ckval != NULL) { // if session cookie is found
            // we bake the cookie to be able to easily access its fields afterwards
            cookie ck = wdn_bake_cookie(r,apr_pstrcat(r->pool,wdn->expected_session_cookies[i],"=",ckval,NULL),r->hostname);;

            // looking for shadow cookie
            ap_cookie_read(r,apr_pstrcat(r->pool,ck.name,WARDEN_SHADOW_POSTFIX,NULL),&swval,false);
            
            if (swval != NULL) {   // we do have a shadow cookie, verify it!
                // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[RWS] we have a shadow cookie");
                cookie ckshadow = wdn_bake_cookie(r,apr_pstrcat(r->pool,wdn->expected_session_cookies[i],WARDEN_SHADOW_POSTFIX,"=",swval,NULL),r->hostname);

                char *ckhmac = calculate_base64_hmac(r,ck.value,strlen(ck.value),wdn->hmac_key,strlen(wdn->hmac_key));

                // if (strcmp(ck.value,ckshadow.value) == 0) { // shadow cookie matches
                if (strcmp(ckhmac,ckshadow.value) == 0) { // shadow cookie matches
                    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[RWS] Shadow cookie HMAC matches");
                } else {    // shadow cookie does not match
                    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[RWS] Shadow cookie HMAC DO NOT matches");
                    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[RWS]  value: %s", ckshadow.value);
                    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[RWS] shadow value: %s", ckshadow.value);
                    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[RWS] What are we doing here?");
                }
            } else {    // we don't have a shadow cookie but if the session cookie is here it has to be verified by a linking cookie, so we expect to be in session
                // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[RWS] we DON'T have a shadow cookie");
                in_session = true;
            }
        }
    }
    return in_session;
}

/*
    strip_cookies_from_request
    removes all the cookies which names are in cklist from those incoming with request r
*/

static void strip_cookies_from_request(request_rec *r, char **cklist) {
    
    // retrieve all cookies in the request
    char *cookies;
    cookies = apr_pstrdup(r->pool,apr_table_getm(r->pool,r->headers_in,"cookie"));
    
    // removes all the cookie headers, we will put back only those that we don't want to strip ;)
    while (apr_table_getm(r->pool,r->headers_in,"cookie")) {
        apr_table_unset(r->headers_in,"cookie");
    }

    int     i;
    char    *newcookiestring = "";
    char    *newcookie;
    bool    stripthis = false;

    if (cookies != NULL) {

        // we cycle throught every cookie in the request
        while (newcookie = apr_strtok(cookies,";",&cookies)) {
            stripthis = false;
            for (i=0;i<WARDEN_SESSION_COOKIES_NUM;i++) {
                // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[WDN STRIPCK] looking for: %s", B[i].name);
                if (strstr(newcookie,cklist[i])) {          // FIXME a little bit rough: we look for the cookie name in the whole cookie string
                    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[WDN STRIPCK] %s found", B[i].name);
                    stripthis = true;
                }
            }

            if (!stripthis) {
                // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[WDN STRIPCK] should add: %s", newcookie);
                newcookiestring = apr_pstrcat(r->pool,newcookiestring,";",newcookie,NULL);
                // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[WDN STRIPCK] new cookie added: %s", newcookiestring);
            }
        }

        apr_table_set(r->headers_in,"cookie",newcookiestring);
    }    
    // cookies = apr_pstrdup(r->pool,apr_table_getm(r->pool,r->headers_in,"cookie"));
    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[WDN STRIPCK] these are the new cookies: %s", cookies_to_remove);
}

/*
    is_cookie_in_jar(char *jar, char *cookie_name)

    helper function to search in the string jar
    a cookie with cookie_name

    FIXME: it actually separate cookies and looks in the whole
    cookie string, rather than just the name

    CHECKME: it has almost the same behaviour/usage as get_cookiestring_from_jar
    maybe we could collapse the two?
*/

static bool is_cookie_in_jar(request_rec *r, char *jar, char *cookie_name) {
    char *localjar = apr_pstrdup(r->pool,jar);
    char *ck;
    while ((ck = strsep(&localjar,";")) != NULL) {
        if (strstr(ck,cookie_name) != NULL) {
            return true;
        }
    }
    return false;
}

static char *get_cookiestring_from_jar(request_rec *r, char * jar, char *cookie_name) {
    char *localjar = apr_pstrdup(r->pool,jar);
    char *ch;

    while ((ch = strsep(&localjar,",")) != NULL) {
        if (strstr(ch,cookie_name) != NULL) {
            return ch;
        }
    }

    return NULL;
}

/*
    wdn_extract_domain
    returns the domain part of uri string

    FIXME: there seems to be a problem with domains with trailing /
    (problem being it doesn't get stripped)
*/
static char* wdn_extract_domain(request_rec *r,char *uri) {
    char *startindex  = strstr(uri,"//");
    char *endindex;
    int domain_len;
    char *ans;

    if (startindex != NULL) {
        endindex = strstr(startindex+2,"/");

        if (endindex != NULL) {
            domain_len  = endindex-startindex-2;    // -2 to compensate for the starting "//" we are going to strip
            ans = apr_pstrndup(r->pool,startindex+2,domain_len);
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[extract domain] got no endindex");
            // returning startindex + 2, which should
            // be the host part without the protocol
            ans = apr_pstrdup(r->pool,startindex + 2);
        }
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[extract domain] using plain uri");
        ans = apr_pstrdup(r->pool,uri);
    }   
    return rtrim(ans,'/'); 
}

/*
    wdn_get_cookie_scope
    returns a cookiescope structure from a cookie
*/

static cookiescope wdn_get_cookie_scope(cookie ck) {
    cookiescope cs;
    if (ck.secure) {
        cs.prot = 'S';  // https
    } else {
        cs.prot = '*';  // http
    }

    strcpy(cs.host,ck.domain);
    strcpy(cs.path,"/");

    return cs;
}

/*
    make_cookie_scope
    returns a cookiescope structure from explicit passed data
*/

static cookiescope make_cookie_scope(request_rec *r,char pr, const char *hs, char *pt) {
    cookiescope cs;
    cs.prot = pr;
    strcpy(cs.host,hs);
    strcpy(cs.path,pt);

    return cs;
}


/*
    wdn_is_dotted_suffix
    returns true if string test is contained in string against

    FIXME: this is just too raw, for dev purpose. it should at least check for the leading dot in string against
*/

static bool wdn_is_dotted_suffix(char *test, char *against) {
    if (strstr(against,test) != NULL)
        return true;
    return false;
}

/*
    is_cookie_scope_leq
    returns true if scope test_this is stricter or equal than test_against
*/

static bool is_cookie_scope_leq(request_rec *r, cookiescope test_this, cookiescope test_against) {
    bool cond1 = false;
    bool cond2 = false;

    if ((test_this.prot == test_against.prot) ||
        (test_against.prot == '*')) {
        cond1 = true;
    }

    if ((strcmp(test_this.host,test_against.host) == 0) ||
        wdn_is_dotted_suffix(test_against.host,test_this.host)) {
        cond2 = true;
    }

    return cond1 && cond2;
}

/*
    wdn_bake_cookie
    returns a cookie structure built examining values in cookie_string string, which is expected
    to hold the string representing data of a single cookie
    base_domain is used to set the cookie domain attribute if not present
    CHECKME: base_domain is actually ALWAYS invoked as r->hostname, which is redundant
        maybe we could remove the variable as its variancy seems to be no longer needed
*/

static cookie wdn_bake_cookie(request_rec *r, char *cookie_string, const char *base_domain) {
    cookie cookme;
    char *tmp;
    char *unescaped_cookie = apr_pstrdup(r->pool,apr_punescape_url(r->pool,cookie_string,NULL,NULL,1));
    // char *unescaped_cookie = apr_pstrdup(r->pool,cookie_string);

    cookme.secure   = false;
    cookme.http_only = false;
    
    if (strstr(unescaped_cookie,";") != NULL) {
        tmp = strsep(&unescaped_cookie,";");
        cookme.name     = apr_pstrdup(r->pool,strsep(&tmp,"="));
        cookme.value    = apr_pstrdup(r->pool,tmp);
        while ((tmp = strsep(&unescaped_cookie,";")) != NULL) {
            if (strstr(tmp,"domain=")) {
                tmp = tmp + 8;
                cookme.domain = apr_pstrdup(r->pool,wdn_extract_domain(r,tmp));
            }

            if (strstr(tmp,"secure")) {
                cookme.secure = true;
            }

            if (strstr(tmp,"HttpOnly")) {
                cookme.http_only = true;
            }
        }
    } else {
        cookme.name     = apr_pstrdup(r->pool,strsep(&unescaped_cookie,"="));
        cookme.value    = apr_pstrdup(r->pool,unescaped_cookie);
        cookme.domain   = apr_pstrdup(r->pool,base_domain);
    }

    if (cookme.domain == "") {
        cookme.domain   = apr_pstrdup(r->pool,base_domain);
    }

    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[bake cookie] Baked cookie.name: %s",cookme.name);
    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[bake cookie] Baked cookie.value: %s",cookme.value);
    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[bake cookie] Baked cookie.domain: %s",cookme.domain);
    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[bake cookie] Baked cookie.secure: %d",cookme.secure);
    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[bake cookie] Baked cookie.http_only: %d",cookme.http_only);

    return cookme;
}

/*
    calculate_base64_hmac
    returns base64 HMAC of data using key key
*/

static char *calculate_base64_hmac(request_rec *r,const char *data, int data_len, unsigned char *key, int key_len) {
    /* HMAC stuff */
    unsigned char *hmac;
    char *base64_hmac;

    wdn_srv_data *wdn =  ap_get_module_config(r->server->module_config, &warden_module);

    if (wdn == NULL)
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[hmac calc] problems getting module config");

    /* calculating HMAC , we used sha512, but dropped to sha1 (128bit) for size reasons */
    hmac = HMAC(EVP_sha1(),key,key_len,data,data_len,NULL,NULL);

    base64_hmac = apr_pcalloc(r->pool,apr_base64_encode_len(strlen(hmac)));
    apr_base64_encode(base64_hmac,hmac,strlen(hmac));

    return apr_pstrcat(r->pool,base64_hmac,NULL);
}

/*
    extract_sessioncookies_from_request
    fills the array passed as parameter res with any incoming cookie in request r
    having one of the names passed in sc
    FIXME: returns true, probably to be removed and set return type to void for consistency
*/

static bool extract_sessioncookies_from_request(request_rec *r, char **sc, cookie *res) {
    int              i;
    const char      *tmpckval;
    char            *cookies_header_string = apr_pstrdup(r->pool,apr_table_getm(r->pool,r->headers_in,"Cookie"));

    for (i=0;i<WARDEN_SESSION_COOKIES_NUM;i++) {
        ap_cookie_read(r,sc[i],&tmpckval,false);
        
        if (tmpckval != NULL) { // if cookie is found
            // we need to unescape the cookie value, and strip everything after the ;
            // as the result of ap_cookie_read holds cookie attributes like Secure and HttpOnly
            res[i]  = wdn_bake_cookie(r,apr_pstrcat(r->pool,sc[i],"=",tmpckval,NULL),r->hostname);
        } else { // cookie not found
            res[i]  = wdn_bake_cookie(r,apr_pstrcat(r->pool,"",NULL),r->hostname);
        }
    }

    return true;
}

/*
    extract_sessioncookies_from_response
    fills the array passed as parameter res with any outgoing cookie in the response to request r
    having one of the names passed in sc
    FIXME: returns true, probably to be removed and set return type to void for consistency
*/

static bool extract_sessioncookies_from_response(request_rec *r, char **sc, cookie *res) {
    int              i;
    char            *cookies_header_string = apr_pstrdup(r->pool,apr_table_getm(r->pool,r->headers_out,"Set-Cookie"));

    for (i=0;i<WARDEN_SESSION_COOKIES_NUM;i++) {
        if (is_cookie_in_jar(r,cookies_header_string,sc[i])) {
            cookie           ck;
            ck = wdn_bake_cookie(r,get_cookiestring_from_jar(r,cookies_header_string,sc[i]),r->hostname);
            if (ck.value != NULL) {
                // CHECKME: do we have to filter away cookies set to expire existing cookies away?
                // e.g. the cookies with + set by wordpress to invalidate current set cookies
                // --> it looks like it's not needed
                res[i] = ck;
            } else {
                res[i] = wdn_bake_cookie(r,apr_pstrcat(r->pool,"",NULL),r->hostname);
            }
        } else {
            res[i] = wdn_bake_cookie(r,apr_pstrcat(r->pool,"",NULL),r->hostname);
        }
    }

    return true;
}

/*
    scope_to_string
    returns a string representing the scope s
    it is used a lot around here! :)
*/

static char *scope_to_string(request_rec *r, cookiescope s) {
    char p[2] = "\0";
    p[0]    = s.prot;
    char *res = apr_pstrcat(r->pool,"_",p,"_",s.host,NULL);
    return res;
}

/*
    is_linking_cookie_valid
    returns true (linking cookie do is valid) if the concatenation of
    the scope,
    the current key/scope id count,
    the plain_to_hmac value
    HMAC's with this session key matches the one in cookie_hmac
*/

static bool is_linking_cookie_valid(request_rec *r, const char *cookie_hmac, char *plain_to_hmac, cookiescope scope, unsigned char *key) {
    
    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] got linking cookie: %s",cookie_hmac);    

    char *own_scope = scope_to_string(r,scope);

    char *b64_key;
    b64_key = apr_pcalloc(r->pool,apr_base64_encode_len(WARDEN_KEY_LENGTH/8));
    apr_base64_encode_binary(b64_key,key,WARDEN_KEY_LENGTH/8);

    char *own_count = get_current_KS_scope_ID(r,b64_key,scope);


    char *hmac_this = apr_pstrcat(r->pool,own_scope,own_count,plain_to_hmac,NULL);

    if (strcmp(cookie_hmac,calculate_base64_hmac(r,hmac_this,strlen(hmac_this),key,WARDEN_KEY_LENGTH/8)) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] linking cookie MISMATCH for %s",r->uri);
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] we were looking for plain: %s",plain_to_hmac);
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] we were looking for scope: %s",own_scope);    
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] we were looking for count: %s",own_count);
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] we were going to hmac: %s",hmac_this);
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] we were testing against: %s",cookie_hmac);
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] but we had: %s",calculate_base64_hmac(r,hmac_this,strlen(hmac_this),key,WARDEN_KEY_LENGTH/8));
        return false;
    }

    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] linking cookie matches");    
    return true;
}

/*
    FILTERING COMMUNICATION BETWEEN BROWSER AND SERVER
*/

static apr_status_t wdn_request_filter(request_rec *r) {
    int ret;
    int i;
 
    cookie      this_request_fakecookie;        // used to create this request scope
    cookiescope this_request_scope;

    char        *strip_these_cookies[WARDEN_SESSION_COOKIES_NUM];   // this will hold a list of session cookie names
    char        *hmac_this = "";

    bool        is_request_valid = true;
    bool        is_login_url = false;

    wdn_srv_data *wdn =  ap_get_module_config(r->server->module_config, &warden_module);
    if (wdn == NULL)
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] problems getting module config");

    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] request for: %s",r->uri);

    if (strcmp(r->uri,wdn->login_URL) == 0) {
        // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] we are in the login page");
        is_login_url = true;
    }

    // retrieving session key
    
    unsigned char *ks = get_KS_from_request(r);
    // TENTATIVE: removing as this seems to invalidate too much
    // if (ks == NULL) {
    //     ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] no KS found, stripping");
    //     // CHECKME: quick and dirty tentative
    //     is_request_valid = false;
    // }

    // Computing request scope
    this_request_fakecookie.domain = apr_pstrdup(r->pool,r->hostname);
    /* maybe raw way to decide if this connection is secure or not */
    if (r->connection->local_addr->port == 443) {
        this_request_fakecookie.secure = true;
    } else {
        this_request_fakecookie.secure = false;
    }
    this_request_scope = wdn_get_cookie_scope(this_request_fakecookie);

    cookie  browser_cookies[WARDEN_SESSION_COOKIES_NUM];
    extract_sessioncookies_from_request(r,wdn->expected_session_cookies,browser_cookies);

    // now we have all the session cookies transmitted by the browser in browser_cookies
    // in each entry either there is a cookie or browser_cookies[i] == ""
    for (i=0;i<WARDEN_SESSION_COOKIES_NUM;i++) {
        strip_these_cookies[i]  = "";   // we use this loop to initialize this variable

        if (strcmp(browser_cookies[i].name,"") != 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] checking shadow cookie for: %s",browser_cookies[i].name);

            const char *shadow;
            ap_cookie_read(r,apr_pstrcat(r->pool,browser_cookies[i].name,WARDEN_SHADOW_POSTFIX,NULL),&shadow,false);
            if (shadow != NULL) {   // we do have a shadow cookie, verify it!
                // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] we have one");
                cookie ckshadow = wdn_bake_cookie(r,apr_pstrcat(r->pool,browser_cookies[i].name,WARDEN_SHADOW_POSTFIX,"=",shadow,NULL),r->hostname);

                char *ckhmac = calculate_base64_hmac(r,browser_cookies[i].value,strlen(browser_cookies[i].value),wdn->hmac_key,strlen(wdn->hmac_key));

                if (strcmp(ckhmac,ckshadow.value) == 0) { // shadow cookie matches
                // if (strcmp(browser_cookies[i].value,ckshadow.value) == 0) { // shadow cookie matches
                    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] Shadow cookie HMAC matches");

                } else {    // shadow cookie does not match
                    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-!>] Shadow cookie HMAC DO NOT matches");
                    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-!>] wanted: %s", ckhmac);
                    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-!>] found : %s", ckshadow.value);
                    is_request_valid = false;
                    strip_these_cookies[i]  = browser_cookies[i].name;
                }
            } else {    // we don't have a shadow cookie, we will verify this cookie via the linking cookie
                ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] we DON'T have one");
                hmac_this = apr_pstrcat(r->pool,hmac_this,browser_cookies[i].value,NULL);
                strip_these_cookies[i]  = browser_cookies[i].name;
            }
        }
    }
    
    if (strcmp(hmac_this,"") != 0) {        // we have to check the linker
        // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] We have to look for a linking cookie");

        /* we need to identify the proper cookie scope to search the HMAC for */
        cookiescope cur_scope;
        cur_scope = make_cookie_scope(r,'*',apr_pstrdup(r->pool,r->hostname),"");     // CHECKME is r->hostname right?
        // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] We built a scope to start from");
        for (i=0;i<WARDEN_SCOPES_NUM;i++) {
            // if ((cookie_scopes[i].prot == '*') || (cookie_scopes[i].prot == 'S')) { // FIXME we would need to populate empty scopes with prot = ' '
                // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] We try scope %d :",i);
                if (is_cookie_scope_leq(r,this_request_scope,wdn->cookie_scopes[i]) &&
                    is_cookie_scope_leq(r,wdn->cookie_scopes[i],cur_scope)) {
                    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] a. %c ",cookie_scopes[i].prot);
                    cur_scope = wdn->cookie_scopes[i];
                    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] ...z");
                }
            // }
        }
        // cur_scope = make_cookie_scope(r,this_request_scope.prot,this_request_scope.host,this_request_scope.path);     // FIXME it works for this partiular case
        // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] We built our temporary scope %c %s",cur_scope.prot,cur_scope.host);
        /* now we have it in cur_scope */

        const char *hmac_cookie;
        ap_cookie_read(r,apr_pstrcat(r->pool,WARDEN_AUTH_COOKIE_NAME,scope_to_string(r,cur_scope),NULL),&hmac_cookie,false);

        if (hmac_cookie != NULL) {
            // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] We found a linking cookie");

            // char *calculatedHMAC = calculate_base64_hmac(r,hmac_this,strlen(hmac_this),wdn->hmac_key,strlen(wdn->hmac_key));
            // if (strcmp(calculatedHMAC,hmac_cookie) == 0) {
            if (is_linking_cookie_valid(r,hmac_cookie,hmac_this,cur_scope,ks)) {
                // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] Linking cookie HMAC matches");
            } else {
                ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-!>] linking cookie HMAC DOES NOT MATCH");
                // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-!>] calculated: %s",calculatedHMAC);
                // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-!>] fromcookie: %s",hmac_cookie);
                is_request_valid = false;
            }

        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-!>] we HAVEN'T found a linking cookie named %s%s",WARDEN_AUTH_COOKIE_NAME,scope_to_string(r,cur_scope));
            is_request_valid = false;
        }
    }

    if (is_request_valid) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-->] letting request pass");
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[-/>] request is not valid: stripping");
        strip_cookies_from_request(r,strip_these_cookies);
    }

    return OK;
}

/*
    debug_this_jar
    this is not actually used, it's kept here should it come handy in the future
    it prints all the cookie in a cookie array jar, prepending jarname for easier identification
*/

static void debug_this_jar(request_rec *r, char *jarname,cookie jar[WARDEN_SESSION_COOKIES_NUM]) {
    int i;

    for(i=0;i<WARDEN_SESSION_COOKIES_NUM;i++) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[CJR] Jar %s - %s[%s]",jarname,jar[i].name,jar[i].value);   
    }
}

/*
    generate_session_key

    generates a key of length WARDEN_KEY_LENGTH
    and returns it in base64 form
*/

static unsigned char *generate_session_key(request_rec *r) {
    unsigned char aes_key[WARDEN_KEY_LENGTH/8];
    memset(aes_key, 0, WARDEN_KEY_LENGTH/8);
    if (!RAND_bytes(aes_key, WARDEN_KEY_LENGTH/8)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<!-] DUH! Problems generating random key");
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] generated session key: %s",aes_key);
    }

    char *base64_aes_key;
    base64_aes_key = apr_pcalloc(r->pool,apr_base64_encode_len(WARDEN_KEY_LENGTH/8));
    apr_base64_encode(base64_aes_key,aes_key,WARDEN_KEY_LENGTH/8);

    return base64_aes_key;
}


/*
    setup_session

    is called when the first authenticators are released and handles
    generating the session key
    storing the session key in the server db with the various scopes
    sending the (encrypted) session key as a cookie
*/

static char *setup_session(request_rec *r) {
    char          *session_key;
    int            affectedRows;
    int            i;
    apr_status_t   res;
    wdn_srv_data  *wdn =  ap_get_module_config(r->server->module_config, &warden_module);

    session_key = apr_pstrcat(r->pool,generate_session_key(r),NULL);
    // now we have the base64 encoded session key in session_key (CHECKME: maybe this base64 encoding is redundant)
    // initializes the key for available scopes
    for (i=0; i<WARDEN_SCOPES_NUM; i++) {
        res = apr_dbd_pvquery(wdn->db_driver,wdn->pool,wdn->db_handle,&affectedRows,wdn->db_new_keyscope,session_key,scope_to_string(r,wdn->cookie_scopes[i]),NULL);
    }
    
    char *key_cookie;
    key_cookie = apr_pstrcat(r->pool,
                            WARDEN_KEY_COOKIE_NAME,
                            "=",
                            encrypt_and_b64_for_cookie_payload(r,session_key,strlen(session_key),wdn->hmac_key),
                            ";",
                            "HttpOnly",
                            NULL);      // CHECKME: maybe this cookie has more attributes (looks like it hasn't)
    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] session key cookie is %s",key_cookie);
    apr_table_add(r->headers_out,"Set-Cookie",key_cookie);

    return session_key;
}

/*
    get_current_KS_scope_ID
    returns a string containing the value found in the DB for the key/scope pair
*/

static char *get_current_KS_scope_ID(request_rec *r, char *key, cookiescope scope) {
    apr_status_t res;
    apr_dbd_results_t *db_result = NULL;    // setting this to NULL solved the segfault
    apr_dbd_row_t *db_row = NULL;           // setting this to NULL solved the segfault
    char *ans = NULL;

    wdn_srv_data *wdn =  ap_get_module_config(r->server->module_config, &warden_module);

    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[CID] I am in with key: %s and scope: %s",key,scope_to_string(r,scope));

    res = apr_dbd_pvselect(wdn->db_driver,wdn->pool,wdn->db_handle,&db_result,wdn->db_get_keyscope_counter,false,key,scope_to_string(r,scope),NULL);
    
    if (res != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[CID] select query error");
    } else {
        /* we should expect just one row, but let's use this format for now */
        for (res = apr_dbd_get_row(wdn->db_driver, wdn->pool, db_result, &db_row, -1);
            res != -1;
            res = apr_dbd_get_row(wdn->db_driver, wdn->pool, db_result, &db_row, -1)) {
            /* rows in table data are in the form key,value */
            if (res != 0)
                ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[CID] problem in parsing select results");
            
            // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[CID] Just before getting the value");
            
            if (db_row == NULL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[CID] no value found for %s",r->connection->client_ip);
            } else {
                // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[CID] some value found");
                ans = apr_pstrdup(wdn->pool,apr_dbd_get_entry(wdn->db_driver,db_row,0));
            }
        }
    }

    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[CID] returning: %s",ans);
    return ans;
}

/*
    increase_scope_ID
    runs a query on the DB to increase the key/scope counter, scope being identified by its
    index i over the cookie_scopes array
*/

static void increase_scope_ID(request_rec *r, char *session_key, int i) {
    wdn_srv_data *wdn =  ap_get_module_config(r->server->module_config, &warden_module);

    if (wdn == NULL)
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] problems getting module config");

    int            affectedRows;
    apr_status_t   res;

    char *scope = apr_pstrdup(r->pool,scope_to_string(r,wdn->cookie_scopes[i]));

    res = apr_dbd_pvquery(wdn->db_driver,wdn->pool,wdn->db_handle,&affectedRows,wdn->db_inc_keyscope_counter,session_key,scope,NULL);
}

/*
    get_KS_from_request
    return plain (not base64) session key from request r if present
    NULL if WARDEN_COOKIE_NAME is not present
*/

unsigned char *get_KS_from_request(request_rec *r) {
    wdn_srv_data *wdn =  ap_get_module_config(r->server->module_config, &warden_module);

    const char *b64_enc_ck = NULL;
    ap_cookie_read(r,WARDEN_KEY_COOKIE_NAME,&b64_enc_ck,false);

    if (b64_enc_ck != NULL) {
        char *b64_ks = unb64_and_decrypt_from_cookie_payload(r,b64_enc_ck,wdn->hmac_key);
        unsigned char *ks;
        int ks_len;
        ks = apr_pcalloc(r->pool,apr_base64_decode_len(b64_ks));
        ks_len = apr_base64_decode_binary(ks,b64_ks);

        return ks;
    } else {
        return NULL;
    }
}

/*
    unb64_and_decrypt_from_cookie_payload
    returns the plaintext (and un-base64ed) value of the data in payload, decrypted using key key
    payload is expected to be constructed in this way:
    <ciphertext>|<encryption tag>
    which is the way encrypt_and_b64_for_cookie_payload constructs payloads to be used as cookies values
*/

static char *unb64_and_decrypt_from_cookie_payload(request_rec *r, const char *payload, unsigned char *key) {
    wdn_srv_data *wdn =  ap_get_module_config(r->server->module_config, &warden_module);

    char *payload_value = apr_pstrdup(r->pool,payload);

    if (key != NULL) {
        char *b64_ciphertext = strsep(&payload_value,"|");
        // after this we should have the base64 ciphertext in b64_ciphertext, and the base64 tag in payload_value
    
        unsigned char *ciphertext;
        int ciphertext_len;
        ciphertext = apr_pcalloc(r->pool,apr_base64_decode_len(b64_ciphertext));
        ciphertext_len = apr_base64_decode_binary(ciphertext,b64_ciphertext);
    
        unsigned char *tag;
        int tag_len;
        tag = apr_pcalloc(r->pool,apr_base64_decode_len(payload_value));
        tag_len = apr_base64_decode_binary(tag,payload_value);
    
        unsigned char plaintext[4096];
        int plaintext_len;
    
        plaintext_len = aesdecrypt(ciphertext, ciphertext_len, wdn->aad, strlen(wdn->aad), tag, key, wdn->iv, plaintext);
        char *realplaintext;
        realplaintext = apr_pstrndup(r->pool,plaintext,plaintext_len);
    
        return realplaintext;
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] NULL key, cannot decrypt");
        return NULL;
    }
}

/*
    encrypt_and_b64_for_cookie_payload
    returns a string which is the base64 version of plaintext encryption under key key
    followed by the | symbol
    followed by encryption tag, for verification
*/

static char *encrypt_and_b64_for_cookie_payload(request_rec *r, unsigned char *plaintext, int plaintext_len, unsigned char *key) {
    wdn_srv_data *wdn =  ap_get_module_config(r->server->module_config, &warden_module);

    unsigned char ciphertext[4096];

    int ciphertext_len = 0;
    /* Buffer for the tag */
    unsigned char           tag[16];

    char *b64_key;
    b64_key = apr_pcalloc(r->pool,apr_base64_encode_len(WARDEN_KEY_LENGTH/8));
    apr_base64_encode_binary(b64_key,key,WARDEN_KEY_LENGTH/8);

    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] Let's encrypt (%d) %s", plaintext_len, plaintext);
    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] with key %s", b64_key);
    ciphertext_len = aesencrypt(plaintext, plaintext_len, wdn->aad, strlen(wdn->aad), key, wdn->iv, ciphertext, tag);

    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] ciphertext is: %d bytes", ciphertext_len);
    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] ciphertext is: %s", ciphertext);

    char *b64_ciphertext;
    b64_ciphertext = apr_pcalloc(r->pool,apr_base64_encode_len(ciphertext_len));
    apr_base64_encode_binary(b64_ciphertext,ciphertext,ciphertext_len);
    // b64_ciphertext holds the encriped session key, now base64 encoded

    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] encoded with tag: %.16s",tag);

    char *b64_tag;
    b64_tag = apr_pcalloc(r->pool,apr_base64_encode_len(16));
    apr_base64_encode_binary(b64_tag,tag,16);

    char *ans;
    ans = apr_pstrcat(r->pool,b64_ciphertext,"|",b64_tag,NULL);

    return ans;
}

/*
    wdn_response_filter

    it parses the response headers looking for certain cookies
    if such cookies are present it adds some more session cookies
*/

static int wdn_response_filter(ap_filter_t *f, apr_bucket_brigade *pbbIn)
{
    int i,j,q;
    request_rec *r = f->r;
    bool is_login_url = false;
    cookie      this_request_fakecookie;        // used to create this request scope
    cookiescope this_request_scope;

    wdn_srv_data *wdn =  ap_get_module_config(r->server->module_config, &warden_module);

    if (wdn == NULL)
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] problems getting module config");

    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] about to call get_KS_from_request");
    unsigned char *ks = get_KS_from_request(r);

    if (strcmp(r->uri,wdn->login_URL) == 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] we are in the login page");
        is_login_url = true;

        // FIXME: this is here but it has probably a better place to be
        if (ks == NULL) {
            char *b64_ks = setup_session(r);
            ks = apr_pcalloc(r->pool,apr_base64_decode_len(b64_ks));
            apr_base64_decode_binary(ks,b64_ks);
        }
    } else {
        // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] we are NOT in the login page");
    }

    // from now on we can assume to have the session key (binary form) in ks, if appliable
    // NULL if we have no session ongoing and we are not in a login page

    // if there's any session cookie without shadow cookie set in the request that spawned this response
    // we consider it in_session (if the cookie made it this far it has to be so)
    bool in_session = are_we_in_session(r,wdn);

    // browser_cookies_in will contain the cookies received with the request
    // it will be useful if we have to rebuild any linking cookie due to cookies present in the response
    cookie  browser_cookies_in[WARDEN_SESSION_COOKIES_NUM];
    extract_sessioncookies_from_request(r,wdn->expected_session_cookies,browser_cookies_in);
    
    // browser_cookies_out contains cookies set by the response
    // and is used to decide if any linking cookie has to be generated/updated
    cookie  browser_cookies_out[WARDEN_SESSION_COOKIES_NUM];
    extract_sessioncookies_from_response(r,wdn->expected_session_cookies,browser_cookies_out);
    

    // Computing request scope
    this_request_fakecookie.domain = apr_pstrdup(r->pool,r->hostname);
    /* maybe raw way to decide if this connection is secure or not */
    if (r->connection->local_addr->port == 443) {
        this_request_fakecookie.secure = true;
    } else {
        this_request_fakecookie.secure = false;
    }
    this_request_scope = wdn_get_cookie_scope(this_request_fakecookie);

    if (in_session || is_login_url) {   // build & send authenticators
            // we have an authenticator per scope each being an array for the various
            // possible cookies values, so we can mantain proper order
            char *scope_authenticators[WARDEN_SCOPES_NUM][WARDEN_SESSION_COOKIES_NUM];
            bool update_this_authenticator[WARDEN_SCOPES_NUM];
            bool remove_this_shadow_cookie[WARDEN_SESSION_COOKIES_NUM];
            
            // initializations
            for(i=0;i<WARDEN_SESSION_COOKIES_NUM;i++) {
                remove_this_shadow_cookie[i] = false;
            }

            for(j=0;j<WARDEN_SCOPES_NUM;j++) {
                for(i=0;i<WARDEN_SESSION_COOKIES_NUM;i++) {
                    scope_authenticators[j][i] = apr_pstrdup(r->pool,"");
                }
                update_this_authenticator[j] = false;
            }

            // append INCOMING cookies to correct scope authenticator
            for (i=0;i<WARDEN_SESSION_COOKIES_NUM;i++) {
                if (strcmp(browser_cookies_in[i].name,"") != 0) {
                    for(j=0;j<WARDEN_SCOPES_NUM;j++) {
                        if (is_cookie_scope_leq(r,wdn->cookie_scopes[j],this_request_scope)) {
                            // FIXME: there are problems with the scopes here
                            // probably the scope of the cookie should be used
                            // not the one of the request
                            ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] adding incoming %s to authenticator for scope %s",browser_cookies_in[i].name,scope_to_string(r,wdn->cookie_scopes[j]));

                            for (q=0;q<WARDEN_SESSION_COOKIES_NUM;q++) {
                                if (strcmp(browser_cookies_in[i].name,wdn->expected_session_cookies[q]) == 0) {
                                    scope_authenticators[j][q] = apr_pstrdup(r->pool,browser_cookies_in[i].value);
                                    remove_this_shadow_cookie[q] = true;
                                    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] added %s ",scope_authenticators[j][q]);    
                                }
                            }

                            // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] scope %s is now: %s",scope_to_string(r,wdn->cookie_scopes[j]),scope_authenticators[j]);
                        }
                    }
                }
            }

            // append OUTGOING cookies to correct scope authenticator
            // mark the outgoing authenticator for updating

            for (i=0;i<WARDEN_SESSION_COOKIES_NUM;i++) {
                
                if (strcmp(browser_cookies_out[i].name,"") != 0) {
                    for(j=0;j<WARDEN_SCOPES_NUM;j++) {
                        if (is_cookie_scope_leq(r,wdn->cookie_scopes[j],this_request_scope)) {
                            // FIXME: there are problems with the scopes here
                            // probably the scope of the cooie should be used
                            // not the one of the request
                            ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] adding outcoming %s to authenticator for scope %s",browser_cookies_out[i].name,scope_to_string(r,wdn->cookie_scopes[j]));
                            // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] scope %d is: %s",j,scope_authenticators[j]);

                            for (q=0;q<WARDEN_SESSION_COOKIES_NUM;q++) {
                                if (strcmp(browser_cookies_out[i].name,wdn->expected_session_cookies[q]) == 0) {
                                    // value of a possibly outgoing cookie will overwrite an incoming one
                                    scope_authenticators[j][q] = apr_pstrdup(r->pool,browser_cookies_out[i].value);
                                    remove_this_shadow_cookie[q] = true;
                                    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] added %s ",scope_authenticators[j][q]);  
                                }
                            }

                            update_this_authenticator[j] = true;
                            // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] scope %d - %s is now: %s",j,scope_to_string(r,wdn->cookie_scopes[j]),scope_authenticators[j]);
                        }
                    }
                }
            }


            char *real_authenticators[WARDEN_SCOPES_NUM];
            for(j=0;j<WARDEN_SCOPES_NUM;j++) {
                real_authenticators[j] = apr_pstrdup(r->pool,"");
                for(i=0;i<WARDEN_SESSION_COOKIES_NUM;i++) {
                    real_authenticators[j] = apr_pstrcat(r->pool,real_authenticators[j],scope_authenticators[j][i],NULL);
                }
                ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] scope %d - %s will HMAC: %s",j,scope_to_string(r,wdn->cookie_scopes[j]),real_authenticators[j]);
            }            

            for (i=0;i<WARDEN_SCOPES_NUM;i++) {
                char *lnk_string;
                char *lnk_attrs = apr_pstrdup(r->pool," HttpOnly; Path=/");

                if (update_this_authenticator[i]) {
                    char *content;
                    
                    char *base64_ks;
                    base64_ks = apr_pcalloc(r->pool,apr_base64_encode_len(WARDEN_KEY_LENGTH/8));
                    apr_base64_encode_binary(base64_ks,ks,WARDEN_KEY_LENGTH/8);
                    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] encoding with base64 key: %s",base64_ks);
                    increase_scope_ID(r,base64_ks,i);
                    
                    // content is the string to be HMAC'd
                    // it shall contain: scope,id number,scope_authenticators[i]
                    content = apr_pstrcat(r->pool,
                                            scope_to_string(r,wdn->cookie_scopes[i]),
                                            get_current_KS_scope_ID(r,base64_ks,wdn->cookie_scopes[i]),
                                            real_authenticators[i],
                                            NULL);
                    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] we are about to send %s",content);

                    lnk_string = apr_pstrcat(r->pool,
                                            WARDEN_AUTH_COOKIE_NAME,
                                            scope_to_string(r,wdn->cookie_scopes[i]),
                                            "=",
                                            calculate_base64_hmac(r,content,strlen(content),ks,WARDEN_KEY_LENGTH/8),
                                            ";",
                                            lnk_attrs,
                                            NULL);
                    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] from %s auth cookie for %s is %s",r->uri,scope_to_string(r,wdn->cookie_scopes[i]),lnk_string);
                    apr_table_add(r->headers_out,"Set-Cookie",lnk_string);

                    /* 
                        removes shadow cookies from the client 
                        FIXME: this operation should be done just one time,
                        instead it is acutally done in its entirety for every
                        authenticator updated. it should be idempotent, anyway
                    */
                    for(i=0;i<WARDEN_SESSION_COOKIES_NUM;i++) {
                        if (remove_this_shadow_cookie[i]) {
                            char *sck_string;
                            char *sck_attrs = apr_pstrdup(r->pool," HttpOnly; Path=/");

                            sck_string = apr_pstrcat(r->pool,
                                                    wdn->expected_session_cookies[i],
                                                    WARDEN_SHADOW_POSTFIX,
                                                    "=;",
                                                    " expires=Thu, Jan 01 1970 00:00:00 UTC;",
                                                    sck_attrs,
                                                    NULL);
                            ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] removing %s",sck_string);
                            apr_table_add(r->headers_out,"Set-Cookie",sck_string);
                        }
                    }

                }
            }

    } else { // build & send shadow cookies
            for (i=0;i<WARDEN_SESSION_COOKIES_NUM;i++) {
                if (strcmp(browser_cookies_out[i].name,"") != 0) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] building shadow cookie for %s",browser_cookies_out[i].name);

                    char *sck_string;
                    char *sck_attrs = apr_pstrdup(r->pool," HttpOnly; Path=/");

                    sck_string = apr_pstrcat(r->pool,
                                            browser_cookies_out[i].name,
                                            WARDEN_SHADOW_POSTFIX,
                                            "=",
                                            calculate_base64_hmac(r,browser_cookies_out[i].value,strlen(browser_cookies_out[i].value),wdn->hmac_key,strlen(wdn->hmac_key)),
                                            ";",
                                            sck_attrs,
                                            NULL);
                    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] %s",sck_string);
                    apr_table_add(r->headers_out,"Set-Cookie",sck_string);
                }
            }
    }


    char            *cookies_header_string = apr_pstrdup(r->pool,apr_table_getm(r->pool,r->headers_out,"Set-Cookie"));
    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[<--] we are sending these cookie headers:%s",cookies_header_string);
    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[WDN OF] answering for %s",r->uri);
    // char *incookies = apr_pstrdup(r->pool,apr_table_getm(r->pool,r->headers_in,"Cookie"));
    // ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "[WDN OF] inbound cookies: %s",incookies);
  
    return ap_pass_brigade(f->next, pbbIn);;
}