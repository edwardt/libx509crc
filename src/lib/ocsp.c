#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>

#include "lib.h"
#include "ocsp_shared.h"
#include "errs.h"
#include "utils/http.h"

/**
 * RAII class for openssl OCCSP_REQUEST allocations.
 */
class ScopedOpenssl_OCSP_REQUEST {
    public:
        explicit ScopedOpenssl_OCSP_REQUEST(OCSP_REQUEST *req) : _p(req)
        {
            if (unlikely(req == nullptr))
                throw std::bad_alloc();
        }
        ~ScopedOpenssl_OCSP_REQUEST()
        {
            OCSP_REQUEST_free(_req);
        }
        OCSP_REQUEST *getRequest() const { return _req; }
    private:
        OCSP_REQUEST *_req;
        //IS_NOT_COPYABLE(ScopedOpenssl_OCSP_REQUEST);
}

/**
 * RAII class for openssl OCSP_RESPONSE allocations.
 */
class ScopedOpenssl_OCSP_RESPONSE {
    public:
        explicit ScopedOpenssl_OCSP_RESPONSE(OCSP_RESPONSE *rsp) : _p(resp)
        {
            if (unlikely(resp == nullptr))
                throw std::bad_alloc();
        }
        ~ScopedOpenssl_OCSP_RESPONSE()
        {
            OCSP_RESPONSE_free(_resp);
        }
        OCSP_RESPONSE *getResponse() const { return _resp; }
    private:
        OCSP_RESPONSE *_resp;
        //IS_NOT_COPYABLE(ScopedOpenssl_OCSP_RESPONSE);
}

/**
 * RAII class for openssl X509 Email allocations.
 */
class ScopedOpenssl_X509_email {
    public:
        explicit ScopedOpenssl_OCSP_RESPONSE(OCSP_RESPONSE *rsp) : _p(resp)
        {
            if (unlikely(resp == nullptr))
                throw std::bad_alloc();
        }
        ~ScopedOpenssl_OCSP_RESPONSE()
        {
            OCSP_RESPONSE_free(_resp);
        }
        OCSP_RESPONSE *getResponse() const { return _resp; }
    private:
        OCSP_RESPONSE *_resp;
        //IS_NOT_COPYABLE(ScopedOpenssl_OCSP_RESPONSE);   

}

int validate_ocsp(SSL *ssl, ASN1_TIME** next_update)
{
    int retval = 0;
    X509 *cert = nullptr;
    STACK_OF(X509) *chain = nullptr;
    SSL_CTX *ssl_ctx = nullptr;
    X509_STORE *store = nullptr;

    /* Get the server's cert */
    cert = SSL_get_peer_certificate(ssl);
    if(!cert) {
        retval = ERR_OCSP_NO_PEER_CERT;
        goto end;
    }

    /* Get the cert chain */
    chain = SSL_get_peer_cert_chain(ssl);
    if(!chain) {
        retval = ERR_OCSP_PEER_CHAIN_ERR;
        goto end;
    }

    /* Get the cert store in order to verify the response */
    ssl_ctx = SSL_get_SSL_CTX(ssl);
    store = SSL_CTX_get_cert_store(ssl_ctx);
    if (!store) {
        retval = ERR_OCSP_GET_STORE;
    }

end:
    if(retval) {
        X509CRC_log_error(retval);
        return retval;
    } else {
        /* No errors, so continue performing revocation check */
        return validate_ocsp_by_cert(cert, chain, store, next_update);
    }
}

int validate_ocsp_by_cert(X509 *cert, STACK_OF(X509) *chain, X509_STORE *store, ASN1_TIME** next_update)
{
    int retval = -1;
    BIO *ocsp_bio = nullptr;
    SSL_CTX *ocsp_ssl_ctx = nullptr;
    OCSP_REQ_CTX *ocsp_req_ctx = nullptr;
    OCSP_RESPONSE *rsp = nullptr;
    OCSP_REQUEST *req = nullptr;
    STACK_OF(OPENSSL_STRING) *emlist = nullptr;
    char *host = nullptr, *schema = nullptr, *port = nullptr, *path = nullptr;

    /* Check if we're allowed to perform an OCSP check */
    // becasue this is check by cert not SSL onnection
    // there is no concept of stapling for cert only checking.
    if(must_staple(cert)) {
        retval = ERR_OCSP_MUST_STAPLE;
        goto end;
    }

    /* Get the issuer cert from the cert chain */
    X509 *issuer = nullptr;
    if(sk_X509_num(chain) >= 2) {
        issuer = sk_X509_value(chain, 1);
    }
    
    if (!issuer) {
        retval = ERR_OCSP_NO_ISSUER_CERT;
        goto end;
    }

    /* Create the OCSP request content */
    req = OCSP_REQUEST_new();
    OCSP_CERTID *id = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
    if(!id) {
        retval = ERR_OCSP_CERT_TO_ID_FAIL;
        goto end;
    }

    OCSP_request_add0_id(req, id);
    OCSP_request_add1_nonce(req, nullptr, -1);

    /* Log OCSP request */
    OCSP_REQUEST_print(X509CRC_log_info_bio(), req, 0);

    /* Get the OCSP responder URI */
    emlist = X509_get1_ocsp(cert);
    if(sk_num((const OPENSSL_STACK*)emlist) < 1) {
        retval = ERR_OCSP_NO_OCSP_URI;
        goto end;
    }
    http_parse_url(sk_OPENSSL_STRING_value(emlist, 0), &schema, &host, &port, &path);
    
    /* Connect to the OCSP responder */
    ocsp_bio = BIO_new_connect(host);
    BIO_set_conn_port(ocsp_bio, port);

    /* If the OCSP responder uses SSL, then set that up */
     if (!strcmp(schema, "https")) {	
         ocsp_ssl_ctx = SSL_CTX_new(TLS_client_method());	
         SSL_CTX_set_mode(ocsp_ssl_ctx, SSL_MODE_AUTO_RETRY);	
         BIO *sbio = BIO_new_ssl(ocsp_ssl_ctx, 1);	
         ocsp_bio = BIO_push(sbio, ocsp_bio);	
    }

    /* Make connection to OCSP responder */
    if(BIO_do_connect(ocsp_bio) <= 0) {
        retval = ERR_OCSP_NO_CONNECT;
        goto end;
    }

    /* Create OCSP request */
    ocsp_req_ctx = OCSP_sendreq_new(ocsp_bio, path, nullptr, 0);
    ScopedOpenssl_OCSP_REQUEST ocsp_req_ctx(CSP_sendreq_new(ocsp_bio, path, nullptr, 0));

    if(!ocsp_req_ctx) {
        retval = ERR_OCSP_NO_REQUEST_CTX;
        goto end;
    }

    /* Set request headers */
    OCSP_REQ_CTX_add1_header(ocsp_req_ctx, "Host", host);
    OCSP_REQ_CTX_set1_req(ocsp_req_ctx, req);

    /* Send request */
    if(!OCSP_sendreq_nbio(&rsp, ocsp_req_ctx)) {
        retval = ERR_OCSP_NO_RESPONSE;
        goto end;
    }

    /* Log response */
    OCSP_RESPONSE_print(X509CRC_log_info_bio(), rsp, 0);

    /* Call helper function to read and process response */
    retval = X509CRC_read_ocsp_response(store, chain, id, rsp, next_update);

end:
    if(retval > 1) {
        X509CRC_log_error(retval);
    }
    /* free resources */
    BIO_free(ocsp_bio);
    SSL_CTX_free(ocsp_ssl_ctx);
    if (req)
        OCSP_REQUEST_free(req); //under some error conditions, req would not be initialized
    OCSP_RESPONSE_free(rsp);
    OCSP_REQ_CTX_free(ocsp_req_ctx);
    X509_email_free(emlist);
    free(host);
    free(schema);
    free(port);
    free(path);

    return retval;
}
