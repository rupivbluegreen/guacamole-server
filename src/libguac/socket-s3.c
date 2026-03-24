/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include "config.h"

#include "guacamole/mem.h"
#include "guacamole/error.h"
#include "guacamole/socket.h"
#include "guacamole/socket-s3.h"

#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * Data associated with a single uploaded S3 part.
 */
typedef struct guac_socket_s3_part {

    /**
     * The 1-based part number.
     */
    int part_number;

    /**
     * The ETag returned by S3 for this part (including quotes).
     */
    char etag[256];

} guac_socket_s3_part;

/**
 * Data associated with an open guac_socket that writes to S3 via multipart
 * upload.
 */
typedef struct guac_socket_s3_data {

    /**
     * The S3 endpoint URL (e.g., "http://minio:9000").
     */
    char* endpoint;

    /**
     * The S3 bucket name.
     */
    char* bucket;

    /**
     * The S3 object key.
     */
    char* key;

    /**
     * The S3 region.
     */
    char* region;

    /**
     * The S3 access key ID.
     */
    char* access_key;

    /**
     * The S3 secret access key.
     */
    char* secret_key;

    /**
     * Whether to use HTTPS.
     */
    int use_ssl;

    /**
     * The multipart upload ID assigned by S3.
     */
    char upload_id[1024];

    /**
     * The internal write buffer. Data accumulates here until it reaches
     * GUAC_SOCKET_S3_MIN_PART_SIZE, at which point it is uploaded as a part.
     */
    char* buffer;

    /**
     * The number of bytes currently in the buffer.
     */
    size_t buffer_used;

    /**
     * The allocated size of the buffer.
     */
    size_t buffer_size;

    /**
     * Array of uploaded part metadata.
     */
    guac_socket_s3_part parts[GUAC_SOCKET_S3_MAX_PARTS];

    /**
     * The number of parts uploaded so far.
     */
    int part_count;

    /**
     * Whether a fatal error has occurred, preventing further uploads.
     */
    int error;

    /**
     * Lock which is acquired when an instruction is being written.
     */
    pthread_mutex_t socket_lock;

    /**
     * Lock which protects access to the internal buffer.
     */
    pthread_mutex_t buffer_lock;

    /**
     * Shared libcurl handle for all S3 requests.
     */
    CURL* curl;

} guac_socket_s3_data;

/**
 * Helper struct for receiving response data from libcurl into a dynamically
 * sized buffer.
 */
typedef struct guac_s3_response {
    char* data;
    size_t size;
} guac_s3_response;

/**
 * Helper struct for providing upload data to libcurl from a memory buffer.
 */
typedef struct guac_s3_upload_context {
    const char* data;
    size_t remaining;
} guac_s3_upload_context;

/**
 * libcurl write callback that appends received data to a guac_s3_response.
 */
static size_t guac_s3_response_write_callback(char* ptr, size_t size,
        size_t nmemb, void* userdata) {

    guac_s3_response* response = (guac_s3_response*) userdata;
    size_t total = size * nmemb;

    char* new_data = realloc(response->data, response->size + total + 1);
    if (new_data == NULL)
        return 0;

    response->data = new_data;
    memcpy(response->data + response->size, ptr, total);
    response->size += total;
    response->data[response->size] = '\0';

    return total;
}

/**
 * libcurl read callback that provides upload data from a memory buffer.
 */
static size_t guac_s3_upload_read_callback(char* buffer, size_t size,
        size_t nmemb, void* userdata) {

    guac_s3_upload_context* ctx = (guac_s3_upload_context*) userdata;
    size_t max_bytes = size * nmemb;
    size_t to_copy = ctx->remaining < max_bytes ? ctx->remaining : max_bytes;

    if (to_copy > 0) {
        memcpy(buffer, ctx->data, to_copy);
        ctx->data += to_copy;
        ctx->remaining -= to_copy;
    }

    return to_copy;
}

/**
 * libcurl header callback that captures the ETag header value.
 */
static size_t guac_s3_header_callback(char* buffer, size_t size,
        size_t nitems, void* userdata) {

    char* etag_out = (char*) userdata;
    size_t total = size * nitems;

    if (total > 5 && strncasecmp(buffer, "ETag:", 5) == 0) {
        /* Skip "ETag:" and leading whitespace */
        const char* value = buffer + 5;
        while (*value == ' ' || *value == '\t')
            value++;

        /* Copy ETag value, strip trailing \r\n */
        size_t len = total - (value - buffer);
        while (len > 0 && (value[len - 1] == '\r' || value[len - 1] == '\n'))
            len--;

        if (len >= 256)
            len = 255;

        memcpy(etag_out, value, len);
        etag_out[len] = '\0';
    }

    return total;
}

/**
 * Computes the hex-encoded SHA-256 hash of the given data.
 *
 * @param data
 *     The data to hash.
 *
 * @param len
 *     The length of the data.
 *
 * @param hex_out
 *     Buffer to receive the 64-character hex string plus NULL terminator.
 *     Must be at least 65 bytes.
 */
static void guac_s3_sha256_hex(const void* data, size_t len, char* hex_out) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*) data, len, hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(hex_out + i * 2, "%02x", hash[i]);
    hex_out[64] = '\0';
}

/**
 * Computes HMAC-SHA256.
 *
 * @param key
 *     The HMAC key.
 *
 * @param key_len
 *     Length of the key.
 *
 * @param data
 *     The data to sign.
 *
 * @param data_len
 *     Length of the data.
 *
 * @param out
 *     Buffer to receive the 32-byte HMAC result.
 */
static void guac_s3_hmac_sha256(const void* key, size_t key_len,
        const void* data, size_t data_len, unsigned char* out) {
    unsigned int out_len = 32;
    HMAC(EVP_sha256(), key, key_len, (const unsigned char*) data,
            data_len, out, &out_len);
}

/**
 * Extracts the host portion from an endpoint URL (strips scheme and trailing
 * slash/port path).
 *
 * @param endpoint
 *     The full endpoint URL.
 *
 * @param host_out
 *     Buffer to receive the host string. Must be at least 512 bytes.
 */
static void guac_s3_extract_host(const char* endpoint, char* host_out) {
    const char* start = strstr(endpoint, "://");
    if (start)
        start += 3;
    else
        start = endpoint;

    /* Copy until '/' or end of string */
    int i = 0;
    while (start[i] && start[i] != '/' && i < 511) {
        host_out[i] = start[i];
        i++;
    }
    host_out[i] = '\0';
}

/**
 * Builds AWS Signature Version 4 Authorization header and related headers
 * for an S3 request.
 *
 * @param data
 *     The S3 socket data containing credentials and endpoint info.
 *
 * @param method
 *     The HTTP method (e.g., "GET", "PUT", "POST", "DELETE").
 *
 * @param uri
 *     The URI path (e.g., "/bucket/key").
 *
 * @param query_string
 *     The query string without leading '?' (e.g., "uploads=" or "").
 *
 * @param payload_hash
 *     The hex-encoded SHA-256 hash of the request payload.
 *
 * @param content_type
 *     The Content-Type header value, or NULL if not applicable.
 *
 * @param headers
 *     Output: pointer to a curl_slist that will be populated with the
 *     required headers. Caller must free with curl_slist_free_all().
 */
static void guac_s3_sign_request(guac_socket_s3_data* data,
        const char* method, const char* uri, const char* query_string,
        const char* payload_hash, const char* content_type,
        struct curl_slist** headers) {

    char host[512];
    guac_s3_extract_host(data->endpoint, host);

    /* Get current UTC time */
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);

    char date_stamp[16]; /* YYYYMMDD */
    char amz_date[32];   /* YYYYMMDD'T'HHMMSS'Z' */
    strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", &tm);
    strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", &tm);

    /* Scope */
    char scope[128];
    snprintf(scope, sizeof(scope), "%s/%s/s3/aws4_request",
            date_stamp, data->region);

    /* Build canonical headers and signed headers */
    char canonical_headers[2048];
    const char* signed_headers;
    if (content_type) {
        snprintf(canonical_headers, sizeof(canonical_headers),
                "content-type:%s\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
                content_type, host, payload_hash, amz_date);
        signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";
    }
    else {
        snprintf(canonical_headers, sizeof(canonical_headers),
                "host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
                host, payload_hash, amz_date);
        signed_headers = "host;x-amz-content-sha256;x-amz-date";
    }

    /* Build canonical request */
    char canonical_request[8192];
    snprintf(canonical_request, sizeof(canonical_request),
            "%s\n%s\n%s\n%s\n%s\n%s",
            method, uri, query_string ? query_string : "",
            canonical_headers, signed_headers, payload_hash);

    /* Hash canonical request */
    char canonical_request_hash[65];
    guac_s3_sha256_hex(canonical_request, strlen(canonical_request),
            canonical_request_hash);

    /* Build string to sign */
    char string_to_sign[4096];
    snprintf(string_to_sign, sizeof(string_to_sign),
            "AWS4-HMAC-SHA256\n%s\n%s\n%s",
            amz_date, scope, canonical_request_hash);

    /* Derive signing key */
    unsigned char date_key[32], region_key[32], service_key[32], signing_key[32];
    char key_prefix[256];
    snprintf(key_prefix, sizeof(key_prefix), "AWS4%s", data->secret_key);

    guac_s3_hmac_sha256(key_prefix, strlen(key_prefix),
            date_stamp, strlen(date_stamp), date_key);
    guac_s3_hmac_sha256(date_key, 32,
            data->region, strlen(data->region), region_key);
    guac_s3_hmac_sha256(region_key, 32, "s3", 2, service_key);
    guac_s3_hmac_sha256(service_key, 32,
            "aws4_request", 12, signing_key);

    /* Compute signature */
    unsigned char signature_bytes[32];
    guac_s3_hmac_sha256(signing_key, 32,
            string_to_sign, strlen(string_to_sign), signature_bytes);

    char signature[65];
    for (int i = 0; i < 32; i++)
        sprintf(signature + i * 2, "%02x", signature_bytes[i]);
    signature[64] = '\0';

    /* Build Authorization header */
    char auth_header[1024];
    snprintf(auth_header, sizeof(auth_header),
            "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, "
            "SignedHeaders=%s, Signature=%s",
            data->access_key, scope, signed_headers, signature);

    /* Build header list */
    char amz_date_header[64];
    snprintf(amz_date_header, sizeof(amz_date_header),
            "x-amz-date: %s", amz_date);

    char amz_content_sha256[128];
    snprintf(amz_content_sha256, sizeof(amz_content_sha256),
            "x-amz-content-sha256: %s", payload_hash);

    *headers = NULL;
    *headers = curl_slist_append(*headers, auth_header);
    *headers = curl_slist_append(*headers, amz_date_header);
    *headers = curl_slist_append(*headers, amz_content_sha256);

    if (content_type) {
        char ct_header[256];
        snprintf(ct_header, sizeof(ct_header), "Content-Type: %s", content_type);
        *headers = curl_slist_append(*headers, ct_header);
    }

    /* Host header */
    char host_header[1024];
    snprintf(host_header, sizeof(host_header), "Host: %s", host);
    *headers = curl_slist_append(*headers, host_header);
}

/**
 * Initiates an S3 multipart upload and stores the upload ID.
 *
 * @param data
 *     The S3 socket data.
 *
 * @return
 *     Zero on success, non-zero on failure.
 */
static int guac_s3_initiate_multipart(guac_socket_s3_data* data) {

    char url[4096];
    char uri[2048];

    snprintf(uri, sizeof(uri), "/%s/%s", data->bucket, data->key);
    snprintf(url, sizeof(url), "%s%s?uploads=", data->endpoint, uri);

    /* Sign the request */
    char payload_hash[65];
    guac_s3_sha256_hex("", 0, payload_hash);

    struct curl_slist* headers = NULL;
    guac_s3_sign_request(data, "POST", uri, "uploads=",
            payload_hash, "application/octet-stream", &headers);

    /* Perform POST to initiate upload */
    guac_s3_response response = { .data = NULL, .size = 0 };

    curl_easy_reset(data->curl);
    curl_easy_setopt(data->curl, CURLOPT_URL, url);
    curl_easy_setopt(data->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(data->curl, CURLOPT_POSTFIELDSIZE, 0L);
    curl_easy_setopt(data->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(data->curl, CURLOPT_WRITEFUNCTION,
            guac_s3_response_write_callback);
    curl_easy_setopt(data->curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(data->curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        free(response.data);
        return 1;
    }

    /* Check HTTP status code */
    long http_code = 0;
    curl_easy_getinfo(data->curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        free(response.data);
        return 1;
    }

    /* Parse UploadId from XML response */
    if (response.data) {
        char* start = strstr(response.data, "<UploadId>");
        char* end = start ? strstr(start, "</UploadId>") : NULL;
        if (start && end) {
            start += 10; /* strlen("<UploadId>") */
            size_t id_len = end - start;
            if (id_len >= sizeof(data->upload_id))
                id_len = sizeof(data->upload_id) - 1;
            memcpy(data->upload_id, start, id_len);
            data->upload_id[id_len] = '\0';
        }
        else {
            free(response.data);
            return 1;
        }
        free(response.data);
    }
    else {
        return 1;
    }

    return 0;
}

/**
 * Uploads a single part of the multipart upload.
 *
 * @param data
 *     The S3 socket data.
 *
 * @param part_data
 *     The data to upload for this part.
 *
 * @param part_size
 *     The size of the data in bytes.
 *
 * @param part_number
 *     The 1-based part number.
 *
 * @return
 *     Zero on success, non-zero on failure.
 */
static int guac_s3_upload_part(guac_socket_s3_data* data,
        const char* part_data, size_t part_size, int part_number) {

    char url[4096];
    char uri[2048];
    char query[2048];

    snprintf(uri, sizeof(uri), "/%s/%s", data->bucket, data->key);
    snprintf(query, sizeof(query), "partNumber=%d&uploadId=%s",
            part_number, data->upload_id);
    snprintf(url, sizeof(url), "%s%s?%s", data->endpoint, uri, query);

    /* Compute payload hash */
    char payload_hash[65];
    guac_s3_sha256_hex(part_data, part_size, payload_hash);

    /* Sign the request */
    struct curl_slist* headers = NULL;
    guac_s3_sign_request(data, "PUT", uri, query,
            payload_hash, "application/octet-stream", &headers);

    /* Set up upload context */
    guac_s3_upload_context upload_ctx = {
        .data = part_data,
        .remaining = part_size
    };

    /* Capture ETag */
    char etag[256] = "";

    curl_easy_reset(data->curl);
    curl_easy_setopt(data->curl, CURLOPT_URL, url);
    curl_easy_setopt(data->curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(data->curl, CURLOPT_READFUNCTION,
            guac_s3_upload_read_callback);
    curl_easy_setopt(data->curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(data->curl, CURLOPT_INFILESIZE_LARGE,
            (curl_off_t) part_size);
    curl_easy_setopt(data->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(data->curl, CURLOPT_HEADERFUNCTION,
            guac_s3_header_callback);
    curl_easy_setopt(data->curl, CURLOPT_HEADERDATA, etag);

    /* Discard response body */
    curl_easy_setopt(data->curl, CURLOPT_WRITEFUNCTION,
            guac_s3_response_write_callback);
    guac_s3_response discard = { .data = NULL, .size = 0 };
    curl_easy_setopt(data->curl, CURLOPT_WRITEDATA, &discard);

    CURLcode res = curl_easy_perform(data->curl);
    curl_slist_free_all(headers);
    free(discard.data);

    if (res != CURLE_OK)
        return 1;

    long http_code = 0;
    curl_easy_getinfo(data->curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200)
        return 1;

    /* Record part info */
    if (data->part_count < GUAC_SOCKET_S3_MAX_PARTS) {
        data->parts[data->part_count].part_number = part_number;
        strncpy(data->parts[data->part_count].etag, etag,
                sizeof(data->parts[data->part_count].etag) - 1);
        data->parts[data->part_count].etag[255] = '\0';
        data->part_count++;
    }

    return 0;
}

/**
 * Completes the multipart upload by sending the list of parts to S3.
 *
 * @param data
 *     The S3 socket data.
 *
 * @return
 *     Zero on success, non-zero on failure.
 */
static int guac_s3_complete_multipart(guac_socket_s3_data* data) {

    /* Build CompleteMultipartUpload XML */
    size_t xml_size = 256 + data->part_count * 512;
    char* xml = guac_mem_alloc(xml_size);
    int offset = 0;

    offset += snprintf(xml + offset, xml_size - offset,
            "<CompleteMultipartUpload>");

    for (int i = 0; i < data->part_count; i++) {
        offset += snprintf(xml + offset, xml_size - offset,
                "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>",
                data->parts[i].part_number, data->parts[i].etag);
    }

    offset += snprintf(xml + offset, xml_size - offset,
            "</CompleteMultipartUpload>");

    /* Build URL */
    char url[4096];
    char uri[2048];
    char query[2048];

    snprintf(uri, sizeof(uri), "/%s/%s", data->bucket, data->key);
    snprintf(query, sizeof(query), "uploadId=%s", data->upload_id);
    snprintf(url, sizeof(url), "%s%s?%s", data->endpoint, uri, query);

    /* Sign the request */
    char payload_hash[65];
    guac_s3_sha256_hex(xml, strlen(xml), payload_hash);

    struct curl_slist* headers = NULL;
    guac_s3_sign_request(data, "POST", uri, query,
            payload_hash, "application/xml", &headers);

    /* Perform POST */
    guac_s3_upload_context upload_ctx = {
        .data = xml,
        .remaining = strlen(xml)
    };

    guac_s3_response response = { .data = NULL, .size = 0 };

    curl_easy_reset(data->curl);
    curl_easy_setopt(data->curl, CURLOPT_URL, url);
    curl_easy_setopt(data->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(data->curl, CURLOPT_READFUNCTION,
            guac_s3_upload_read_callback);
    curl_easy_setopt(data->curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(data->curl, CURLOPT_POSTFIELDSIZE_LARGE,
            (curl_off_t) strlen(xml));
    curl_easy_setopt(data->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(data->curl, CURLOPT_WRITEFUNCTION,
            guac_s3_response_write_callback);
    curl_easy_setopt(data->curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(data->curl);
    curl_slist_free_all(headers);
    guac_mem_free(xml);
    free(response.data);

    if (res != CURLE_OK)
        return 1;

    long http_code = 0;
    curl_easy_getinfo(data->curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200)
        return 1;

    return 0;
}

/**
 * Aborts the multipart upload.
 *
 * @param data
 *     The S3 socket data.
 */
static void guac_s3_abort_multipart(guac_socket_s3_data* data) {

    char url[4096];
    char uri[2048];
    char query[2048];

    snprintf(uri, sizeof(uri), "/%s/%s", data->bucket, data->key);
    snprintf(query, sizeof(query), "uploadId=%s", data->upload_id);
    snprintf(url, sizeof(url), "%s%s?%s", data->endpoint, uri, query);

    char payload_hash[65];
    guac_s3_sha256_hex("", 0, payload_hash);

    struct curl_slist* headers = NULL;
    guac_s3_sign_request(data, "DELETE", uri, query,
            payload_hash, NULL, &headers);

    curl_easy_reset(data->curl);
    curl_easy_setopt(data->curl, CURLOPT_URL, url);
    curl_easy_setopt(data->curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(data->curl, CURLOPT_HTTPHEADER, headers);

    /* Discard response */
    curl_easy_setopt(data->curl, CURLOPT_WRITEFUNCTION,
            guac_s3_response_write_callback);
    guac_s3_response discard = { .data = NULL, .size = 0 };
    curl_easy_setopt(data->curl, CURLOPT_WRITEDATA, &discard);

    curl_easy_perform(data->curl);
    curl_slist_free_all(headers);
    free(discard.data);
}

/**
 * Global pointer to the most recently created S3 socket data, used by the
 * SIGTERM handler to complete pending multipart uploads on shutdown.
 */
static guac_socket_s3_data* guac_s3_active_socket = NULL;

/**
 * Previous SIGTERM handler, saved for chaining.
 */
static struct sigaction guac_s3_prev_sigterm;

/**
 * SIGTERM handler that attempts to complete any pending S3 multipart uploads
 * before the process exits.
 */
static void guac_s3_sigterm_handler(int sig) {

    guac_socket_s3_data* data = guac_s3_active_socket;

    if (data != NULL && !data->error && data->upload_id[0] != '\0') {

        /* Upload any remaining buffered data as the final part */
        if (data->buffer_used > 0) {
            guac_s3_upload_part(data, data->buffer, data->buffer_used,
                    data->part_count + 1);
        }

        /* Complete the multipart upload if any parts were uploaded */
        if (data->part_count > 0)
            guac_s3_complete_multipart(data);

    }

    /* Chain to previous handler or use default behavior */
    if (guac_s3_prev_sigterm.sa_handler != SIG_DFL
            && guac_s3_prev_sigterm.sa_handler != SIG_IGN)
        guac_s3_prev_sigterm.sa_handler(sig);
    else
        _exit(0);
}

/**
 * Flushes the contents of the output buffer, uploading it as a part if the
 * buffer has reached the minimum part size or if force_flush is non-zero.
 * This function must ONLY be called if the buffer lock has already been
 * acquired.
 *
 * @param socket
 *     The guac_socket to flush.
 *
 * @param force_flush
 *     Non-zero if the buffer should be flushed regardless of size (used
 *     during final flush before completing the upload).
 *
 * @return
 *     Zero on success, non-zero on failure.
 */
static ssize_t guac_socket_s3_flush_internal(guac_socket* socket,
        int force_flush) {

    guac_socket_s3_data* data = (guac_socket_s3_data*) socket->data;

    if (data->error)
        return 1;

    /* Only flush if buffer has reached minimum part size, or if forced */
    if (data->buffer_used == 0)
        return 0;

    if (!force_flush && data->buffer_used < GUAC_SOCKET_S3_MIN_PART_SIZE)
        return 0;

    /* Upload the buffered data as a part */
    int part_number = data->part_count + 1;
    if (guac_s3_upload_part(data, data->buffer, data->buffer_used,
                part_number)) {
        data->error = 1;
        guac_error = GUAC_STATUS_INTERNAL_ERROR;
        guac_error_message = "Failed to upload S3 part";
        return 1;
    }

    data->buffer_used = 0;
    return 0;
}

/**
 * Flush handler for the S3 socket. Acquires the buffer lock and flushes
 * if the buffer has reached the minimum part size.
 */
static ssize_t guac_socket_s3_flush_handler(guac_socket* socket) {

    guac_socket_s3_data* data = (guac_socket_s3_data*) socket->data;

    pthread_mutex_lock(&(data->buffer_lock));
    ssize_t retval = guac_socket_s3_flush_internal(socket, 0);
    pthread_mutex_unlock(&(data->buffer_lock));

    return retval;
}

/**
 * Write handler for the S3 socket. Appends data to the internal buffer
 * and triggers an upload when the buffer reaches the minimum part size.
 */
static ssize_t guac_socket_s3_write_handler(guac_socket* socket,
        const void* buf, size_t count) {

    guac_socket_s3_data* data = (guac_socket_s3_data*) socket->data;
    const char* current = buf;

    if (data->error) {
        guac_error = GUAC_STATUS_INTERNAL_ERROR;
        guac_error_message = "S3 socket in error state";
        return -1;
    }

    pthread_mutex_lock(&(data->buffer_lock));

    while (count > 0) {

        /* Calculate space remaining in buffer */
        size_t remaining = data->buffer_size - data->buffer_used;

        /* If buffer is full, flush it */
        if (remaining == 0) {
            if (guac_socket_s3_flush_internal(socket, 0)) {
                pthread_mutex_unlock(&(data->buffer_lock));
                return -1;
            }
            remaining = data->buffer_size - data->buffer_used;
        }

        /* Copy as much as possible to buffer */
        size_t chunk = count < remaining ? count : remaining;
        memcpy(data->buffer + data->buffer_used, current, chunk);
        data->buffer_used += chunk;

        current += chunk;
        count -= chunk;

        /* Auto-flush if buffer reached minimum part size */
        if (data->buffer_used >= GUAC_SOCKET_S3_MIN_PART_SIZE) {
            if (guac_socket_s3_flush_internal(socket, 0)) {
                pthread_mutex_unlock(&(data->buffer_lock));
                return -1;
            }
        }
    }

    pthread_mutex_unlock(&(data->buffer_lock));
    return 0;
}

/**
 * Free handler for the S3 socket. Flushes any remaining data as the final
 * part, completes (or aborts) the multipart upload, and cleans up resources.
 */
static int guac_socket_s3_free_handler(guac_socket* socket) {

    guac_socket_s3_data* data = (guac_socket_s3_data*) socket->data;

    /* If no error, flush remaining buffer and complete the upload */
    if (!data->error) {

        /* Upload any remaining data as the final part */
        if (data->buffer_used > 0) {
            if (guac_s3_upload_part(data, data->buffer, data->buffer_used,
                        data->part_count + 1)) {
                data->error = 1;
            }
        }

        /* Complete or abort based on state */
        if (!data->error && data->part_count > 0) {
            if (guac_s3_complete_multipart(data))
                data->error = 1;
        }
    }

    /* If there was an error and we have an upload ID, abort */
    if (data->error && data->upload_id[0] != '\0')
        guac_s3_abort_multipart(data);

    /* Clear global reference so signal handler won't act on freed data */
    if (guac_s3_active_socket == data)
        guac_s3_active_socket = NULL;

    /* Clean up */
    curl_easy_cleanup(data->curl);
    pthread_mutex_destroy(&(data->socket_lock));
    pthread_mutex_destroy(&(data->buffer_lock));
    guac_mem_free(data->buffer);
    guac_mem_free(data->endpoint);
    guac_mem_free(data->bucket);
    guac_mem_free(data->key);
    guac_mem_free(data->region);
    guac_mem_free(data->access_key);
    guac_mem_free(data->secret_key);
    guac_mem_free(data);

    return 0;
}

/**
 * Lock handler for the S3 socket.
 */
static void guac_socket_s3_lock_handler(guac_socket* socket) {
    guac_socket_s3_data* data = (guac_socket_s3_data*) socket->data;
    pthread_mutex_lock(&(data->socket_lock));
}

/**
 * Unlock handler for the S3 socket.
 */
static void guac_socket_s3_unlock_handler(guac_socket* socket) {
    guac_socket_s3_data* data = (guac_socket_s3_data*) socket->data;
    pthread_mutex_unlock(&(data->socket_lock));
}

guac_socket* guac_socket_open_s3(const char* endpoint, const char* bucket,
        const char* key, const char* region, const char* access_key,
        const char* secret_key, int use_ssl) {

    pthread_mutexattr_t lock_attributes;

    /* Allocate socket and associated data */
    guac_socket* socket = guac_socket_alloc();
    guac_socket_s3_data* data = guac_mem_alloc(sizeof(guac_socket_s3_data));
    memset(data, 0, sizeof(guac_socket_s3_data));

    /* Copy S3 configuration */
    data->endpoint = guac_mem_alloc(strlen(endpoint) + 1);
    strcpy(data->endpoint, endpoint);

    data->bucket = guac_mem_alloc(strlen(bucket) + 1);
    strcpy(data->bucket, bucket);

    data->key = guac_mem_alloc(strlen(key) + 1);
    strcpy(data->key, key);

    data->region = guac_mem_alloc(strlen(region) + 1);
    strcpy(data->region, region);

    data->access_key = guac_mem_alloc(strlen(access_key) + 1);
    strcpy(data->access_key, access_key);

    data->secret_key = guac_mem_alloc(strlen(secret_key) + 1);
    strcpy(data->secret_key, secret_key);

    data->use_ssl = use_ssl;

    /* Allocate buffer (slightly larger than min part size to avoid frequent
     * flushes) */
    data->buffer_size = GUAC_SOCKET_S3_MIN_PART_SIZE + (1024 * 1024);
    data->buffer = guac_mem_alloc(data->buffer_size);
    data->buffer_used = 0;
    data->part_count = 0;
    data->error = 0;
    data->upload_id[0] = '\0';

    /* Initialize libcurl */
    data->curl = curl_easy_init();
    if (data->curl == NULL) {
        guac_mem_free(data->buffer);
        guac_mem_free(data->endpoint);
        guac_mem_free(data->bucket);
        guac_mem_free(data->key);
        guac_mem_free(data->region);
        guac_mem_free(data->access_key);
        guac_mem_free(data->secret_key);
        guac_mem_free(data);
        guac_socket_free(socket);
        guac_error = GUAC_STATUS_INTERNAL_ERROR;
        guac_error_message = "Failed to initialize libcurl";
        return NULL;
    }

    /* Initialize mutexes */
    pthread_mutexattr_init(&lock_attributes);
    pthread_mutexattr_setpshared(&lock_attributes, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&(data->socket_lock), &lock_attributes);
    pthread_mutex_init(&(data->buffer_lock), &lock_attributes);

    /* Initiate the multipart upload */
    if (guac_s3_initiate_multipart(data)) {
        curl_easy_cleanup(data->curl);
        pthread_mutex_destroy(&(data->socket_lock));
        pthread_mutex_destroy(&(data->buffer_lock));
        guac_mem_free(data->buffer);
        guac_mem_free(data->endpoint);
        guac_mem_free(data->bucket);
        guac_mem_free(data->key);
        guac_mem_free(data->region);
        guac_mem_free(data->access_key);
        guac_mem_free(data->secret_key);
        guac_mem_free(data);
        guac_socket_free(socket);
        guac_error = GUAC_STATUS_INTERNAL_ERROR;
        guac_error_message = "Failed to initiate S3 multipart upload";
        return NULL;
    }

    /* Set socket data and handlers */
    socket->data = data;
    socket->read_handler = NULL;     /* Write-only socket */
    socket->write_handler = guac_socket_s3_write_handler;
    socket->select_handler = NULL;   /* Write-only socket */
    socket->lock_handler = guac_socket_s3_lock_handler;
    socket->unlock_handler = guac_socket_s3_unlock_handler;
    socket->flush_handler = guac_socket_s3_flush_handler;
    socket->free_handler = guac_socket_s3_free_handler;

    /* Register SIGTERM handler to complete uploads on shutdown */
    guac_s3_active_socket = data;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = guac_s3_sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, &guac_s3_prev_sigterm);

    return socket;
}
