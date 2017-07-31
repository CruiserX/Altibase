/**
 *  Copyright (c) 1999~2017, Altibase Corp. and/or its affiliates. All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License, version 3,
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <cmAllClient.h>
#include <cmnOpensslClient.h>

#if !defined(CM_DISABLE_SSL)

/* In case of client connections, it is allowable
 * if the client couldn't load the openssl library at cmiInitialize().
 * Therefore, the following two variables store a real error code and message
 * to let the client know the accurate reason for the failure of the library initialization
 * and are returned to the client at the appropriate time. */
#define SSL_LIB_ERROR_MSG_LEN (ACI_MAX_ERROR_MSG_LEN+256)  /* aciErrorMsg.h */
acp_uint32_t     gSslLibErrorCode = cmERR_IGNORE_NoError;
acp_char_t       gSslLibErrorMsg[SSL_LIB_ERROR_MSG_LEN] = {0,};

cmnOpensslFuncs *gOpenssl = NULL;

static acp_dl_t       gSslHandle;
static acp_dl_t       gCryptoHandle;

ACI_RC cmnOpensslInitialize(cmnOpensslFuncs **aOpenssl)
{
    acp_rc_t sRC = ACP_RC_SUCCESS;
    acp_dl_t *sSslHandle = &gSslHandle;
    acp_dl_t *sCryptoHandle = &gCryptoHandle;

    cmnOpensslFuncs *sOpenssl = NULL;

    sRC = acpDlOpen(sSslHandle, NULL, ALTIBASE_OPENSSL_LIB_NAME, ACP_TRUE);
    ACI_TEST_RAISE(sRC != ACP_RC_SUCCESS, ERR_DLOPEN_LIBSSL);

    sRC = acpDlOpen(sCryptoHandle, NULL, ALTIBASE_CRYPTO_LIB_NAME, ACP_TRUE);
    ACI_TEST_RAISE(sRC != ACP_RC_SUCCESS, ERR_DLOPEN_LIBCRYPTO);

    ACI_TEST(acpMemAlloc((void **)&sOpenssl, sizeof(cmnOpensslFuncs)) != ACP_RC_SUCCESS);

    /* load functions */
    *(void**)&sOpenssl->SSL_library_init = acpDlSym(sSslHandle, "SSL_library_init");
    ACI_TEST_RAISE(sOpenssl->SSL_library_init == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->OPENSSL_add_all_algorithms_noconf = acpDlSym(sCryptoHandle, 
                                                                     "OPENSSL_add_all_algorithms_noconf");
    ACI_TEST_RAISE(sOpenssl->OPENSSL_add_all_algorithms_noconf == NULL, ERR_DLSYM_LIBCRYPTO);

    sOpenssl->OpenSSL_add_all_algorithms = sOpenssl->OPENSSL_add_all_algorithms_noconf;

    *(void**)&sOpenssl->SSL_CTX_new = acpDlSym(sSslHandle, "SSL_CTX_new");
    ACI_TEST_RAISE(sOpenssl->SSL_CTX_new == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->TLSv1_server_method = acpDlSym(sSslHandle, "TLSv1_server_method");
    ACI_TEST_RAISE(sOpenssl->TLSv1_server_method == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->TLSv1_client_method = acpDlSym(sSslHandle, "TLSv1_client_method");
    ACI_TEST_RAISE(sOpenssl->TLSv1_client_method == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_CTX_set_info_callback = acpDlSym(sSslHandle, "SSL_CTX_set_info_callback");
    ACI_TEST_RAISE(sOpenssl->SSL_CTX_set_info_callback == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_CTX_use_certificate_file = acpDlSym(sSslHandle, "SSL_CTX_use_certificate_file");
    ACI_TEST_RAISE(sOpenssl->SSL_CTX_use_certificate_file == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_CTX_set_default_passwd_cb = acpDlSym(sSslHandle, "SSL_CTX_set_default_passwd_cb");
    ACI_TEST_RAISE(sOpenssl->SSL_CTX_set_default_passwd_cb == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_CTX_use_PrivateKey_file = acpDlSym(sSslHandle, "SSL_CTX_use_PrivateKey_file");
    ACI_TEST_RAISE(sOpenssl->SSL_CTX_use_PrivateKey_file == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_CTX_check_private_key = acpDlSym(sSslHandle, "SSL_CTX_check_private_key");
    ACI_TEST_RAISE(sOpenssl->SSL_CTX_check_private_key == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_CTX_set_cipher_list = acpDlSym(sSslHandle, "SSL_CTX_set_cipher_list");
    ACI_TEST_RAISE(sOpenssl->SSL_CTX_set_cipher_list == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_get_current_cipher = acpDlSym(sSslHandle, "SSL_get_current_cipher");
    ACI_TEST_RAISE(sOpenssl->SSL_get_current_cipher == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_CIPHER_get_name = acpDlSym(sSslHandle, "SSL_CIPHER_get_name");
    ACI_TEST_RAISE(sOpenssl->SSL_CIPHER_get_name == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_CTX_set_verify_depth = acpDlSym(sSslHandle, "SSL_CTX_set_verify_depth");
    ACI_TEST_RAISE(sOpenssl->SSL_CTX_set_verify_depth == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_CTX_load_verify_locations = acpDlSym(sSslHandle, "SSL_CTX_load_verify_locations");
    ACI_TEST_RAISE(sOpenssl->SSL_CTX_load_verify_locations == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_CTX_set_default_verify_paths = acpDlSym(sSslHandle, "SSL_CTX_set_default_verify_paths");
    ACI_TEST_RAISE(sOpenssl->SSL_CTX_set_default_verify_paths == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_CTX_ctrl = acpDlSym(sSslHandle, "SSL_CTX_ctrl");
    ACI_TEST_RAISE(sOpenssl->SSL_CTX_ctrl == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_CTX_set_client_CA_list = acpDlSym(sSslHandle, "SSL_CTX_set_client_CA_list");
    ACI_TEST_RAISE(sOpenssl->SSL_CTX_set_client_CA_list == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_CTX_set_verify = acpDlSym(sSslHandle, "SSL_CTX_set_verify");
    ACI_TEST_RAISE(sOpenssl->SSL_CTX_set_verify == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_CTX_free = acpDlSym(sSslHandle, "SSL_CTX_free");
    ACI_TEST_RAISE(sOpenssl->SSL_CTX_free == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_set_quiet_shutdown = acpDlSym(sSslHandle, "SSL_set_quiet_shutdown");
    ACI_TEST_RAISE(sOpenssl->SSL_set_quiet_shutdown == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_get_peer_certificate = acpDlSym(sSslHandle, "SSL_get_peer_certificate");
    ACI_TEST_RAISE(sOpenssl->SSL_get_peer_certificate == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_get_verify_result = acpDlSym(sSslHandle, "SSL_get_verify_result");
    ACI_TEST_RAISE(sOpenssl->SSL_get_verify_result == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_load_client_CA_file = acpDlSym(sSslHandle, "SSL_load_client_CA_file");
    ACI_TEST_RAISE(sOpenssl->SSL_load_client_CA_file == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_set_cipher_list = acpDlSym(sSslHandle, "SSL_set_cipher_list");
    ACI_TEST_RAISE(sOpenssl->SSL_set_cipher_list == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_shutdown = acpDlSym(sSslHandle, "SSL_shutdown");
    ACI_TEST_RAISE(sOpenssl->SSL_shutdown == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_free = acpDlSym(sSslHandle, "SSL_free");
    ACI_TEST_RAISE(sOpenssl->SSL_free == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_get_error = acpDlSym(sSslHandle, "SSL_get_error");
    ACI_TEST_RAISE(sOpenssl->SSL_get_error == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_load_error_strings = acpDlSym(sSslHandle, "SSL_load_error_strings");
    ACI_TEST_RAISE(sOpenssl->SSL_load_error_strings == NULL, ERR_DLSYM_LIBSSL);

    /* BUG-44488 */
    /* OpenSSL does not provide any cleanup functions for the resources allocated by itself.
     * Therefore, the following functions should be called to avoid memory leaks.
     * See also https://wiki.openssl.org/index.php/Library_Initialization */
    *(void**)&sOpenssl->ERR_free_strings = acpDlSym(sSslHandle, "ERR_free_strings");
    ACI_TEST_RAISE(sOpenssl->ERR_free_strings == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->ERR_remove_state = acpDlSym(sSslHandle, "ERR_remove_state");
    ACI_TEST_RAISE(sOpenssl->ERR_remove_state == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->EVP_cleanup = acpDlSym(sSslHandle, "EVP_cleanup");
    ACI_TEST_RAISE(sOpenssl->EVP_cleanup == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->ENGINE_cleanup = acpDlSym(sCryptoHandle, "ENGINE_cleanup");
    ACI_TEST_RAISE(sOpenssl->ENGINE_cleanup == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->CONF_modules_unload = acpDlSym(sCryptoHandle, "CONF_modules_unload");
    ACI_TEST_RAISE(sOpenssl->CONF_modules_unload == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->CRYPTO_cleanup_all_ex_data = acpDlSym(sCryptoHandle, "CRYPTO_cleanup_all_ex_data");
    ACI_TEST_RAISE(sOpenssl->CRYPTO_cleanup_all_ex_data == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->FIPS_mode_set = acpDlSym(sCryptoHandle, "FIPS_mode_set");
    ACI_TEST_RAISE(sOpenssl->FIPS_mode_set == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->CRYPTO_set_locking_callback = acpDlSym(sCryptoHandle, "CRYPTO_set_locking_callback");
    ACI_TEST_RAISE(sOpenssl->CRYPTO_set_locking_callback == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->CRYPTO_set_id_callback = acpDlSym(sCryptoHandle, "CRYPTO_set_id_callback");
    ACI_TEST_RAISE(sOpenssl->CRYPTO_set_id_callback == NULL, ERR_DLSYM_LIBSSL);

#if (OPENSSL_VERSION_NUMBER >= 0x1000200fL)
    *(void**)&sOpenssl->SSL_COMP_free_compression_methods = acpDlSym(sSslHandle, "SSL_COMP_free_compression_methods");
    ACI_TEST_RAISE(sOpenssl->SSL_COMP_free_compression_methods == NULL, ERR_DLSYM_LIBSSL);
#endif  

    /* BUG-41166 SSL multi platform */
    *(void**)&sOpenssl->ERR_error_string = acpDlSym(sSslHandle, "ERR_error_string");
    ACI_TEST_RAISE(sOpenssl->ERR_error_string == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->ERR_get_error = acpDlSym(sSslHandle, "ERR_get_error");
    ACI_TEST_RAISE(sOpenssl->ERR_get_error == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_read = acpDlSym(sSslHandle, "SSL_read");
    ACI_TEST_RAISE(sOpenssl->SSL_read == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_write = acpDlSym(sSslHandle, "SSL_write");
    ACI_TEST_RAISE(sOpenssl->SSL_write == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_new = acpDlSym(sSslHandle, "SSL_new");
    ACI_TEST_RAISE(sOpenssl->SSL_new == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_connect = acpDlSym(sSslHandle, "SSL_connect");
    ACI_TEST_RAISE(sOpenssl->SSL_connect == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_set_fd = acpDlSym(sSslHandle, "SSL_set_fd");
    ACI_TEST_RAISE(sOpenssl->SSL_set_fd == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_accept = acpDlSym(sSslHandle, "SSL_accept");
    ACI_TEST_RAISE(sOpenssl->SSL_accept == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_state_string_long = acpDlSym(sSslHandle, "SSL_state_string_long");
    ACI_TEST_RAISE(sOpenssl->SSL_state_string_long == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_alert_type_string_long = acpDlSym(sSslHandle, "SSL_alert_type_string_long");
    ACI_TEST_RAISE(sOpenssl->SSL_alert_type_string_long == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->SSL_alert_desc_string_long = acpDlSym(sSslHandle, "SSL_alert_desc_string_long");
    ACI_TEST_RAISE(sOpenssl->SSL_alert_desc_string_long == NULL, ERR_DLSYM_LIBSSL);
    
    *(void**)&sOpenssl->X509_NAME_oneline = acpDlSym(sSslHandle, "X509_NAME_oneline");
    ACI_TEST_RAISE(sOpenssl->X509_NAME_oneline == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->X509_get_subject_name = acpDlSym(sSslHandle, "X509_get_subject_name");
    ACI_TEST_RAISE(sOpenssl->X509_get_subject_name == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->X509_NAME_oneline = acpDlSym(sSslHandle, "X509_NAME_oneline");
    ACI_TEST_RAISE(sOpenssl->X509_NAME_oneline == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->X509_get_issuer_name = acpDlSym(sSslHandle, "X509_get_issuer_name");
    ACI_TEST_RAISE(sOpenssl->X509_get_issuer_name == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->X509_NAME_get_text_by_NID = acpDlSym(sSslHandle, "X509_NAME_get_text_by_NID");
    ACI_TEST_RAISE(sOpenssl->X509_NAME_get_text_by_NID == NULL, ERR_DLSYM_LIBSSL);

    *(void**)&sOpenssl->X509_free = acpDlSym(sSslHandle, "X509_free");
    ACI_TEST_RAISE(sOpenssl->X509_free == NULL, ERR_DLSYM_LIBSSL);

    /* Initialize SSL/TLS */
    sOpenssl->SSL_library_init(); /* register all ciphers and has algorithms used in SSL APIs. */
    sOpenssl->OpenSSL_add_all_algorithms(); /* load and register all cryptos, etc */
    sOpenssl->SSL_load_error_strings(); /* load error strings for SSL APIs as well as for Crypto APIs. */

    *aOpenssl = sOpenssl;

    return ACI_SUCCESS;

    ACI_EXCEPTION( ERR_DLSYM_LIBSSL )
    {
        ACI_SET(aciSetErrorCode(cmERR_ABORT_DLSYM, ALTIBASE_OPENSSL_LIB_NAME, acpDlError(sSslHandle)));
    }
    ACI_EXCEPTION( ERR_DLSYM_LIBCRYPTO )
    {
        ACI_SET(aciSetErrorCode(cmERR_ABORT_DLSYM, ALTIBASE_CRYPTO_LIB_NAME, acpDlError(sCryptoHandle)));
    }
    ACI_EXCEPTION( ERR_DLOPEN_LIBSSL)
    {
        ACI_SET(aciSetErrorCode(cmERR_ABORT_DLOPEN, ALTIBASE_OPENSSL_LIB_NAME, acpDlError(sSslHandle)));
    }
    ACI_EXCEPTION( ERR_DLOPEN_LIBCRYPTO )
    {
        ACI_SET(aciSetErrorCode(cmERR_ABORT_DLOPEN, ALTIBASE_CRYPTO_LIB_NAME, acpDlError(sCryptoHandle)));
    }
    ACI_EXCEPTION_END;

    gSslLibErrorCode = aciGetErrorCode();
    acpSnprintf(gSslLibErrorMsg, SSL_LIB_ERROR_MSG_LEN, "%s", aciGetErrorMsg(gSslLibErrorCode));

    (void)cmnOpensslDestroy(aOpenssl);

    return ACI_FAILURE;     
}

static ACI_RC cmnOpensslCleanUpLibrary(cmnOpensslFuncs *aOpenssl)
{
    ACI_TEST(aOpenssl == NULL);

#if (OPENSSL_VERSION_NUMBER >= 0x1000200fL)
    /* Release the internal table of compression methods built internally */
    aOpenssl->SSL_COMP_free_compression_methods();
#endif

    /* Exit the FIPS mode of operation */
    (void)aOpenssl->FIPS_mode_set(0);

    /* Release shared global data structures */
    aOpenssl->CRYPTO_set_locking_callback(NULL);
    aOpenssl->CRYPTO_set_id_callback(NULL);
    /* According to the OpenSSL website, 
     * CRYPTO_set_id_callback() should be called on each thread;
     * however, this causes an application crash by a double-free error 
     * if every thread calls the function. */
    aOpenssl->CRYPTO_cleanup_all_ex_data();

    /* Free error strings */
    aOpenssl->ERR_free_strings();

    /* Remove all ciphers and digests from the internal table for them */
    aOpenssl->EVP_cleanup();

    /* Unload ENGINE objects */
    aOpenssl->ENGINE_cleanup();

    /* Finish and unload configuration modules (1: All modules) */
    aOpenssl->CONF_modules_unload(1);

    return ACI_SUCCESS;

    ACI_EXCEPTION_END;

    return ACI_FAILURE;
}

ACI_RC cmnOpensslDestroy(cmnOpensslFuncs **aOpenssl)
{
    cmnOpensslFuncs *sOpenssl = *aOpenssl;

    if ( sOpenssl == NULL )
    {
        (void)cmnOpensslCleanUpLibrary(sOpenssl);

        acpMemFree(*aOpenssl);
        *aOpenssl = NULL;
    }
  
    if (gSslHandle.mHandle != NULL)
    {
        (void)acpDlClose(&gSslHandle);
        gSslHandle.mHandle = NULL;
    }
    else
    {
        /* gSslHandle is null */
    }

    if (gCryptoHandle.mHandle != NULL)
    {
        (void)acpDlClose(&gCryptoHandle);
        gCryptoHandle.mHandle = NULL;
    }
    else
    {
        /* gCryptoHandle is null */
    }

    return ACI_SUCCESS;
}

const acp_char_t *cmnOpensslErrorMessage(cmnOpensslFuncs *aOpenssl)
{
    ACI_TEST_RAISE(gOpenssl == NULL, NoSslLibrary);

    return aOpenssl->ERR_error_string(aOpenssl->ERR_get_error(), NULL);

    ACI_EXCEPTION(NoSslLibrary)
    {
        aciSetErrorCodeAndMsg(gSslLibErrorCode, gSslLibErrorMsg);
    }
    ACI_EXCEPTION_END;

    return (acp_char_t *)NULL;
}

#endif /* CM_DISABLE_SSL */
