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

#include "common/io.h"
#include "terminal/typescript.h"

#include <guacamole/file.h>
#include <guacamole/mem.h>
#include <guacamole/timestamp.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef ENABLE_S3
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <time.h>
#endif

guac_terminal_typescript* guac_terminal_typescript_alloc(const char* path,
        const char* name, int create_path, int allow_write_existing) {

    /* Allocate space for new typescript */
    guac_terminal_typescript* typescript =
        guac_mem_alloc(sizeof(guac_terminal_typescript));

    guac_open_how data_how = {
        .oflags = O_CREAT | O_WRONLY,
        .mode = S_IRUSR | S_IWUSR | S_IRGRP,
        .filename = typescript->data_filename,
        .filename_size = sizeof(typescript->data_filename)
    };

    if (create_path)
        data_how.flags |= GUAC_O_CREATE_PATH;

    if (!allow_write_existing)
        data_how.flags |= GUAC_O_UNIQUE_SUFFIX;

    /* Attempt to open typescript data file */
    typescript->data_fd = guac_openat(path, name, &data_how);
    if (typescript->data_fd == -1) {
        guac_mem_free(typescript);
        return NULL;
    }

    /* Append suffix to basename */
    if (snprintf(typescript->timing_filename, sizeof(typescript->timing_filename),
                "%s.%s", typescript->data_filename, GUAC_TERMINAL_TYPESCRIPT_TIMING_SUFFIX)
            >= sizeof(typescript->timing_filename)) {
        close(typescript->data_fd);
        guac_mem_free(typescript);
        return NULL;
    }

    guac_open_how timing_how = {
        .oflags = O_CREAT | O_WRONLY,
        .mode = S_IRUSR | S_IWUSR | S_IRGRP
    };

    /* Attempt to open typescript timing file */
    typescript->timing_fd = guac_openat(path, typescript->timing_filename, &timing_how);
    if (typescript->timing_fd == -1) {
        close(typescript->data_fd);
        guac_mem_free(typescript);
        return NULL;
    }

    /* Typescript starts out flushed */
    typescript->length = 0;
    typescript->last_flush = guac_timestamp_current();

#ifdef ENABLE_S3
    /* Not using S3 for local typescripts */
    typescript->use_s3 = 0;
#endif

    /* Write header */
    guac_common_write(typescript->data_fd, GUAC_TERMINAL_TYPESCRIPT_HEADER,
            sizeof(GUAC_TERMINAL_TYPESCRIPT_HEADER) - 1);

    return typescript;

}

void guac_terminal_typescript_write(guac_terminal_typescript* typescript,
        char c) {

    /* Flush buffer if no space is available */
    if (typescript->length == sizeof(typescript->buffer))
        guac_terminal_typescript_flush(typescript);

    /* Append single byte to buffer */
    typescript->buffer[typescript->length++] = c;

}

#ifdef ENABLE_S3
static int guac_ts_s3_stream_write(guac_ts_s3_stream* stream,
        const char* data, size_t length);
#endif

void guac_terminal_typescript_flush(guac_terminal_typescript* typescript) {

    /* Do nothing if nothing to flush */
    if (typescript->length == 0)
        return;

    /* Get timestamps of previous and current flush */
    guac_timestamp this_flush = guac_timestamp_current();
    guac_timestamp last_flush = typescript->last_flush;

    /* Calculate time since last flush */
    int elapsed_time = this_flush - last_flush;
    if (elapsed_time > GUAC_TERMINAL_TYPESCRIPT_MAX_DELAY)
        elapsed_time = GUAC_TERMINAL_TYPESCRIPT_MAX_DELAY;

    /* Produce single line of timestamp output */
    char timestamp_buffer[32];
    int timestamp_length = snprintf(timestamp_buffer, sizeof(timestamp_buffer),
            "%0.6f %i\n", elapsed_time / 1000.0, typescript->length);

    /* Calculate actual length of timestamp line */
    if (timestamp_length > sizeof(timestamp_buffer))
        timestamp_length = sizeof(timestamp_buffer);

#ifdef ENABLE_S3
    if (typescript->use_s3) {
        /* Write timing and data directly to S3 streams */
        guac_ts_s3_stream_write(typescript->s3_timing_stream,
                timestamp_buffer, timestamp_length);
        guac_ts_s3_stream_write(typescript->s3_data_stream,
                typescript->buffer, typescript->length);
    }
    else {
#endif

    /* Write timestamp to timing file */
    guac_common_write(typescript->timing_fd,
            timestamp_buffer, timestamp_length);

    /* Empty buffer into data file */
    guac_common_write(typescript->data_fd,
            typescript->buffer, typescript->length);

#ifdef ENABLE_S3
    }
#endif

    /* Buffer is now flushed */
    typescript->length = 0;
    typescript->last_flush = this_flush;

}

#ifdef ENABLE_S3

/**
 * The minimum size of an S3 multipart upload part, in bytes. All parts except
 * the last must be at least this size.
 */
#define GUAC_TS_S3_MIN_PART_SIZE (5 * 1024 * 1024)

/**
 * The maximum number of parts in an S3 multipart upload.
 */
#define GUAC_TS_S3_MAX_PARTS 10000

/**
 * Helper struct for receiving response data from libcurl.
 */
typedef struct guac_ts_s3_response {
    char* data;
    size_t size;
} guac_ts_s3_response;

/**
 * Helper struct for providing upload data to libcurl from a memory buffer.
 */
typedef struct guac_ts_s3_upload_context {
    const char* data;
    size_t remaining;
} guac_ts_s3_upload_context;

/**
 * Data associated with a single uploaded S3 part.
 */
typedef struct guac_ts_s3_part {
    int part_number;
    char etag[256];
} guac_ts_s3_part;

/**
 * An S3 multipart upload stream. Data is buffered internally and uploaded
 * as parts when the buffer fills. The upload is completed on close.
 */
struct guac_ts_s3_stream {

    /** The S3 endpoint URL. */
    char* endpoint;

    /** The S3 bucket name. */
    char* bucket;

    /** The S3 object key. */
    char* key;

    /** The S3 region. */
    char* region;

    /** The S3 access key ID. */
    char* access_key;

    /** The S3 secret access key. */
    char* secret_key;

    /** The multipart upload ID assigned by S3. */
    char upload_id[1024];

    /** Internal write buffer. */
    char* buffer;

    /** Number of bytes currently in the buffer. */
    size_t buffer_used;

    /** Allocated size of the buffer. */
    size_t buffer_size;

    /** Array of uploaded part metadata. */
    guac_ts_s3_part parts[GUAC_TS_S3_MAX_PARTS];

    /** Number of parts uploaded so far. */
    int part_count;

    /** Whether a fatal error has occurred. */
    int error;

    /** Shared libcurl handle for all S3 requests. */
    CURL* curl;

};

/**
 * libcurl write callback for receiving response data.
 */
static size_t guac_ts_s3_write_callback(char* ptr, size_t size,
        size_t nmemb, void* userdata) {
    guac_ts_s3_response* response = (guac_ts_s3_response*) userdata;
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
 * libcurl read callback for providing upload data from a memory buffer.
 */
static size_t guac_ts_s3_read_callback(char* buffer, size_t size,
        size_t nmemb, void* userdata) {
    guac_ts_s3_upload_context* ctx = (guac_ts_s3_upload_context*) userdata;
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
static size_t guac_ts_s3_header_callback(char* buffer, size_t size,
        size_t nitems, void* userdata) {
    char* etag_out = (char*) userdata;
    size_t total = size * nitems;
    if (total > 5 && strncasecmp(buffer, "ETag:", 5) == 0) {
        const char* value = buffer + 5;
        while (*value == ' ' || *value == '\t')
            value++;
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
 */
static void guac_ts_sha256_hex(const void* data, size_t len, char* hex_out) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*) data, len, hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(hex_out + i * 2, "%02x", hash[i]);
    hex_out[64] = '\0';
}

/**
 * Computes HMAC-SHA256.
 */
static void guac_ts_hmac_sha256(const void* key, size_t key_len,
        const void* data, size_t data_len, unsigned char* out) {
    unsigned int out_len = 32;
    HMAC(EVP_sha256(), key, key_len, (const unsigned char*) data,
            data_len, out, &out_len);
}

/**
 * Extracts the host portion from an endpoint URL.
 */
static void guac_ts_extract_host(const char* endpoint, char* host_out) {
    const char* start = strstr(endpoint, "://");
    if (start)
        start += 3;
    else
        start = endpoint;
    int i = 0;
    while (start[i] && start[i] != '/' && i < 511) {
        host_out[i] = start[i];
        i++;
    }
    host_out[i] = '\0';
}

/**
 * Builds AWS Signature Version 4 headers for an S3 request.
 */
static void guac_ts_s3_sign_request(guac_ts_s3_stream* stream,
        const char* method, const char* uri, const char* query_string,
        const char* payload_hash, const char* content_type,
        struct curl_slist** headers) {

    char host[512];
    guac_ts_extract_host(stream->endpoint, host);

    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);

    char date_stamp[16];
    char amz_date[32];
    strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", &tm);
    strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", &tm);

    char scope[128];
    snprintf(scope, sizeof(scope), "%s/%s/s3/aws4_request",
            date_stamp, stream->region);

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

    char canonical_request[8192];
    snprintf(canonical_request, sizeof(canonical_request),
            "%s\n%s\n%s\n%s\n%s\n%s",
            method, uri, query_string ? query_string : "",
            canonical_headers, signed_headers, payload_hash);

    char canonical_request_hash[65];
    guac_ts_sha256_hex(canonical_request, strlen(canonical_request),
            canonical_request_hash);

    char string_to_sign[4096];
    snprintf(string_to_sign, sizeof(string_to_sign),
            "AWS4-HMAC-SHA256\n%s\n%s\n%s",
            amz_date, scope, canonical_request_hash);

    unsigned char date_key[32], region_key[32], service_key[32], signing_key[32];
    char key_prefix[256];
    snprintf(key_prefix, sizeof(key_prefix), "AWS4%s", stream->secret_key);
    guac_ts_hmac_sha256(key_prefix, strlen(key_prefix),
            date_stamp, strlen(date_stamp), date_key);
    guac_ts_hmac_sha256(date_key, 32,
            stream->region, strlen(stream->region), region_key);
    guac_ts_hmac_sha256(region_key, 32, "s3", 2, service_key);
    guac_ts_hmac_sha256(service_key, 32, "aws4_request", 12, signing_key);

    unsigned char signature_bytes[32];
    guac_ts_hmac_sha256(signing_key, 32,
            string_to_sign, strlen(string_to_sign), signature_bytes);

    char signature[65];
    for (int i = 0; i < 32; i++)
        sprintf(signature + i * 2, "%02x", signature_bytes[i]);
    signature[64] = '\0';

    char auth_header[1024];
    snprintf(auth_header, sizeof(auth_header),
            "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, "
            "SignedHeaders=%s, Signature=%s",
            stream->access_key, scope, signed_headers, signature);

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

    char host_header[1024];
    snprintf(host_header, sizeof(host_header), "Host: %s", host);
    *headers = curl_slist_append(*headers, host_header);
}

/**
 * Initiates an S3 multipart upload and stores the upload ID in the stream.
 *
 * @return
 *     Zero on success, non-zero on failure.
 */
static int guac_ts_s3_initiate_multipart(guac_ts_s3_stream* stream) {

    char url[4096];
    char uri[2048];

    snprintf(uri, sizeof(uri), "/%s/%s", stream->bucket, stream->key);
    snprintf(url, sizeof(url), "%s%s?uploads=", stream->endpoint, uri);

    char payload_hash[65];
    guac_ts_sha256_hex("", 0, payload_hash);

    struct curl_slist* headers = NULL;
    guac_ts_s3_sign_request(stream, "POST", uri, "uploads=",
            payload_hash, "application/octet-stream", &headers);

    guac_ts_s3_response response = { .data = NULL, .size = 0 };

    curl_easy_reset(stream->curl);
    curl_easy_setopt(stream->curl, CURLOPT_URL, url);
    curl_easy_setopt(stream->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(stream->curl, CURLOPT_POSTFIELDSIZE, 0L);
    curl_easy_setopt(stream->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(stream->curl, CURLOPT_WRITEFUNCTION,
            guac_ts_s3_write_callback);
    curl_easy_setopt(stream->curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(stream->curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        free(response.data);
        return 1;
    }

    long http_code = 0;
    curl_easy_getinfo(stream->curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        free(response.data);
        return 1;
    }

    /* Parse UploadId from XML response */
    if (response.data) {
        char* start = strstr(response.data, "<UploadId>");
        char* end = start ? strstr(start, "</UploadId>") : NULL;
        if (start && end) {
            start += 10;
            size_t id_len = end - start;
            if (id_len >= sizeof(stream->upload_id))
                id_len = sizeof(stream->upload_id) - 1;
            memcpy(stream->upload_id, start, id_len);
            stream->upload_id[id_len] = '\0';
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
 * @return
 *     Zero on success, non-zero on failure.
 */
static int guac_ts_s3_upload_part(guac_ts_s3_stream* stream,
        const char* part_data, size_t part_size, int part_number) {

    char url[4096];
    char uri[2048];
    char query[2048];

    snprintf(uri, sizeof(uri), "/%s/%s", stream->bucket, stream->key);
    snprintf(query, sizeof(query), "partNumber=%d&uploadId=%s",
            part_number, stream->upload_id);
    snprintf(url, sizeof(url), "%s%s?%s", stream->endpoint, uri, query);

    char payload_hash[65];
    guac_ts_sha256_hex(part_data, part_size, payload_hash);

    struct curl_slist* headers = NULL;
    guac_ts_s3_sign_request(stream, "PUT", uri, query,
            payload_hash, "application/octet-stream", &headers);

    guac_ts_s3_upload_context upload_ctx = {
        .data = part_data,
        .remaining = part_size
    };

    char etag[256] = "";

    curl_easy_reset(stream->curl);
    curl_easy_setopt(stream->curl, CURLOPT_URL, url);
    curl_easy_setopt(stream->curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(stream->curl, CURLOPT_READFUNCTION,
            guac_ts_s3_read_callback);
    curl_easy_setopt(stream->curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(stream->curl, CURLOPT_INFILESIZE_LARGE,
            (curl_off_t) part_size);
    curl_easy_setopt(stream->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(stream->curl, CURLOPT_HEADERFUNCTION,
            guac_ts_s3_header_callback);
    curl_easy_setopt(stream->curl, CURLOPT_HEADERDATA, etag);

    guac_ts_s3_response discard = { .data = NULL, .size = 0 };
    curl_easy_setopt(stream->curl, CURLOPT_WRITEFUNCTION,
            guac_ts_s3_write_callback);
    curl_easy_setopt(stream->curl, CURLOPT_WRITEDATA, &discard);

    CURLcode res = curl_easy_perform(stream->curl);
    curl_slist_free_all(headers);
    free(discard.data);

    if (res != CURLE_OK)
        return 1;

    long http_code = 0;
    curl_easy_getinfo(stream->curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200)
        return 1;

    if (stream->part_count < GUAC_TS_S3_MAX_PARTS) {
        stream->parts[stream->part_count].part_number = part_number;
        strncpy(stream->parts[stream->part_count].etag, etag,
                sizeof(stream->parts[stream->part_count].etag) - 1);
        stream->parts[stream->part_count].etag[255] = '\0';
        stream->part_count++;
    }

    return 0;
}

/**
 * Completes the multipart upload by sending the list of parts to S3.
 *
 * @return
 *     Zero on success, non-zero on failure.
 */
static int guac_ts_s3_complete_multipart(guac_ts_s3_stream* stream) {

    size_t xml_size = 256 + stream->part_count * 512;
    char* xml = guac_mem_alloc(xml_size);
    int offset = 0;

    offset += snprintf(xml + offset, xml_size - offset,
            "<CompleteMultipartUpload>");

    for (int i = 0; i < stream->part_count; i++) {
        offset += snprintf(xml + offset, xml_size - offset,
                "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>",
                stream->parts[i].part_number, stream->parts[i].etag);
    }

    offset += snprintf(xml + offset, xml_size - offset,
            "</CompleteMultipartUpload>");

    char url[4096];
    char uri[2048];
    char query[2048];

    snprintf(uri, sizeof(uri), "/%s/%s", stream->bucket, stream->key);
    snprintf(query, sizeof(query), "uploadId=%s", stream->upload_id);
    snprintf(url, sizeof(url), "%s%s?%s", stream->endpoint, uri, query);

    char payload_hash[65];
    guac_ts_sha256_hex(xml, strlen(xml), payload_hash);

    struct curl_slist* headers = NULL;
    guac_ts_s3_sign_request(stream, "POST", uri, query,
            payload_hash, "application/xml", &headers);

    guac_ts_s3_upload_context upload_ctx = {
        .data = xml,
        .remaining = strlen(xml)
    };

    guac_ts_s3_response response = { .data = NULL, .size = 0 };

    curl_easy_reset(stream->curl);
    curl_easy_setopt(stream->curl, CURLOPT_URL, url);
    curl_easy_setopt(stream->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(stream->curl, CURLOPT_READFUNCTION,
            guac_ts_s3_read_callback);
    curl_easy_setopt(stream->curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(stream->curl, CURLOPT_POSTFIELDSIZE_LARGE,
            (curl_off_t) strlen(xml));
    curl_easy_setopt(stream->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(stream->curl, CURLOPT_WRITEFUNCTION,
            guac_ts_s3_write_callback);
    curl_easy_setopt(stream->curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(stream->curl);
    curl_slist_free_all(headers);
    guac_mem_free(xml);
    free(response.data);

    if (res != CURLE_OK)
        return 1;

    long http_code = 0;
    curl_easy_getinfo(stream->curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200)
        return 1;

    return 0;
}

/**
 * Aborts the multipart upload.
 */
static void guac_ts_s3_abort_multipart(guac_ts_s3_stream* stream) {

    char url[4096];
    char uri[2048];
    char query[2048];

    snprintf(uri, sizeof(uri), "/%s/%s", stream->bucket, stream->key);
    snprintf(query, sizeof(query), "uploadId=%s", stream->upload_id);
    snprintf(url, sizeof(url), "%s%s?%s", stream->endpoint, uri, query);

    char payload_hash[65];
    guac_ts_sha256_hex("", 0, payload_hash);

    struct curl_slist* headers = NULL;
    guac_ts_s3_sign_request(stream, "DELETE", uri, query,
            payload_hash, NULL, &headers);

    curl_easy_reset(stream->curl);
    curl_easy_setopt(stream->curl, CURLOPT_URL, url);
    curl_easy_setopt(stream->curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(stream->curl, CURLOPT_HTTPHEADER, headers);

    guac_ts_s3_response discard = { .data = NULL, .size = 0 };
    curl_easy_setopt(stream->curl, CURLOPT_WRITEFUNCTION,
            guac_ts_s3_write_callback);
    curl_easy_setopt(stream->curl, CURLOPT_WRITEDATA, &discard);

    curl_easy_perform(stream->curl);
    curl_slist_free_all(headers);
    free(discard.data);
}

/**
 * Opens a new S3 multipart upload stream.
 *
 * @return
 *     A new guac_ts_s3_stream, or NULL on failure.
 */
static guac_ts_s3_stream* guac_ts_s3_stream_open(const char* endpoint,
        const char* bucket, const char* key, const char* region,
        const char* access_key, const char* secret_key, size_t buffer_size) {

    guac_ts_s3_stream* stream = guac_mem_alloc(sizeof(guac_ts_s3_stream));
    memset(stream, 0, sizeof(guac_ts_s3_stream));

    stream->endpoint = guac_mem_alloc(strlen(endpoint) + 1);
    strcpy(stream->endpoint, endpoint);

    stream->bucket = guac_mem_alloc(strlen(bucket) + 1);
    strcpy(stream->bucket, bucket);

    stream->key = guac_mem_alloc(strlen(key) + 1);
    strcpy(stream->key, key);

    stream->region = guac_mem_alloc(strlen(region) + 1);
    strcpy(stream->region, region);

    stream->access_key = guac_mem_alloc(strlen(access_key) + 1);
    strcpy(stream->access_key, access_key);

    stream->secret_key = guac_mem_alloc(strlen(secret_key) + 1);
    strcpy(stream->secret_key, secret_key);

    stream->buffer_size = buffer_size;
    stream->buffer = guac_mem_alloc(buffer_size);
    stream->buffer_used = 0;
    stream->part_count = 0;
    stream->error = 0;
    stream->upload_id[0] = '\0';

    stream->curl = curl_easy_init();
    if (stream->curl == NULL) {
        guac_mem_free(stream->buffer);
        guac_mem_free(stream->endpoint);
        guac_mem_free(stream->bucket);
        guac_mem_free(stream->key);
        guac_mem_free(stream->region);
        guac_mem_free(stream->access_key);
        guac_mem_free(stream->secret_key);
        guac_mem_free(stream);
        return NULL;
    }

    if (guac_ts_s3_initiate_multipart(stream)) {
        curl_easy_cleanup(stream->curl);
        guac_mem_free(stream->buffer);
        guac_mem_free(stream->endpoint);
        guac_mem_free(stream->bucket);
        guac_mem_free(stream->key);
        guac_mem_free(stream->region);
        guac_mem_free(stream->access_key);
        guac_mem_free(stream->secret_key);
        guac_mem_free(stream);
        return NULL;
    }

    return stream;
}

/**
 * Writes data to an S3 stream. Data is buffered and uploaded as parts when
 * the buffer reaches the minimum part size.
 *
 * @return
 *     Zero on success, non-zero on failure.
 */
static int guac_ts_s3_stream_write(guac_ts_s3_stream* stream,
        const char* data, size_t length) {

    if (stream->error)
        return 1;

    while (length > 0) {

        size_t remaining = stream->buffer_size - stream->buffer_used;

        /* If buffer is full, flush it */
        if (remaining == 0) {
            int part_number = stream->part_count + 1;
            if (guac_ts_s3_upload_part(stream, stream->buffer,
                        stream->buffer_used, part_number)) {
                stream->error = 1;
                return 1;
            }
            stream->buffer_used = 0;
            remaining = stream->buffer_size;
        }

        size_t chunk = length < remaining ? length : remaining;
        memcpy(stream->buffer + stream->buffer_used, data, chunk);
        stream->buffer_used += chunk;
        data += chunk;
        length -= chunk;

        /* Auto-flush if buffer reached minimum part size */
        if (stream->buffer_used >= GUAC_TS_S3_MIN_PART_SIZE) {
            int part_number = stream->part_count + 1;
            if (guac_ts_s3_upload_part(stream, stream->buffer,
                        stream->buffer_used, part_number)) {
                stream->error = 1;
                return 1;
            }
            stream->buffer_used = 0;
        }
    }

    return 0;
}

/**
 * Closes an S3 stream, uploading any remaining buffered data as the final
 * part and completing (or aborting) the multipart upload. Frees all resources.
 */
static void guac_ts_s3_stream_close(guac_ts_s3_stream* stream) {

    if (stream == NULL)
        return;

    /* Upload any remaining buffered data as the final part */
    if (!stream->error && stream->buffer_used > 0) {
        int part_number = stream->part_count + 1;
        if (guac_ts_s3_upload_part(stream, stream->buffer,
                    stream->buffer_used, part_number)) {
            stream->error = 1;
        }
    }

    /* Complete or abort the multipart upload */
    if (!stream->error && stream->part_count > 0)
        guac_ts_s3_complete_multipart(stream);
    else if (stream->error && stream->upload_id[0] != '\0')
        guac_ts_s3_abort_multipart(stream);

    /* Free all resources */
    curl_easy_cleanup(stream->curl);
    guac_mem_free(stream->buffer);
    guac_mem_free(stream->endpoint);
    guac_mem_free(stream->bucket);
    guac_mem_free(stream->key);
    guac_mem_free(stream->region);
    guac_mem_free(stream->access_key);
    guac_mem_free(stream->secret_key);
    guac_mem_free(stream);
}

guac_terminal_typescript* guac_terminal_typescript_alloc_s3(const char* name,
        const char* endpoint, const char* bucket, const char* key,
        const char* region, const char* access_key, const char* secret_key) {

    /* Build S3 key for timing file */
    char timing_key[2048];
    snprintf(timing_key, sizeof(timing_key), "%s.timing", key);

    /* Open S3 multipart upload streams for data and timing */
    guac_ts_s3_stream* data_stream = guac_ts_s3_stream_open(endpoint, bucket,
            key, region, access_key, secret_key,
            GUAC_TS_S3_MIN_PART_SIZE + (1024 * 1024));
    if (data_stream == NULL)
        return NULL;

    guac_ts_s3_stream* timing_stream = guac_ts_s3_stream_open(endpoint, bucket,
            timing_key, region, access_key, secret_key,
            256 * 1024);
    if (timing_stream == NULL) {
        guac_ts_s3_stream_close(data_stream);
        return NULL;
    }

    /* Allocate typescript structure */
    guac_terminal_typescript* typescript =
        guac_mem_alloc(sizeof(guac_terminal_typescript));

    /* No local file descriptors */
    typescript->data_fd = -1;
    typescript->timing_fd = -1;

    /* Store S3 streams */
    typescript->use_s3 = 1;
    typescript->s3_data_stream = data_stream;
    typescript->s3_timing_stream = timing_stream;

    /* Initialize buffer state */
    typescript->length = 0;
    typescript->last_flush = guac_timestamp_current();

    /* Set filenames for logging purposes */
    snprintf(typescript->data_filename, sizeof(typescript->data_filename),
            "%s", name);
    snprintf(typescript->timing_filename, sizeof(typescript->timing_filename),
            "%s.%s", name, GUAC_TERMINAL_TYPESCRIPT_TIMING_SUFFIX);

    /* Write typescript header directly to S3 data stream */
    guac_ts_s3_stream_write(data_stream, GUAC_TERMINAL_TYPESCRIPT_HEADER,
            sizeof(GUAC_TERMINAL_TYPESCRIPT_HEADER) - 1);

    return typescript;

}

#endif /* ENABLE_S3 */

void guac_terminal_typescript_free(guac_terminal_typescript* typescript) {

    /* Do nothing if no typescript provided */
    if (typescript == NULL)
        return;

    /* Flush any pending data */
    guac_terminal_typescript_flush(typescript);

#ifdef ENABLE_S3
    if (typescript->use_s3) {

        /* Write footer directly to S3 data stream */
        guac_ts_s3_stream_write(typescript->s3_data_stream,
                GUAC_TERMINAL_TYPESCRIPT_FOOTER,
                sizeof(GUAC_TERMINAL_TYPESCRIPT_FOOTER) - 1);

        /* Complete both multipart uploads */
        guac_ts_s3_stream_close(typescript->s3_data_stream);
        guac_ts_s3_stream_close(typescript->s3_timing_stream);

        guac_mem_free(typescript);
        return;
    }
#endif

    /* Write footer to local file */
    guac_common_write(typescript->data_fd, GUAC_TERMINAL_TYPESCRIPT_FOOTER,
            sizeof(GUAC_TERMINAL_TYPESCRIPT_FOOTER) - 1);

    /* Close file descriptors */
    close(typescript->data_fd);
    close(typescript->timing_fd);

    /* Free allocated typescript data */
    guac_mem_free(typescript);

}
