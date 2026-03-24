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

    /* Write timestamp to timing file */
    guac_common_write(typescript->timing_fd,
            timestamp_buffer, timestamp_length);

    /* Empty buffer into data file */
    guac_common_write(typescript->data_fd,
            typescript->buffer, typescript->length);

    /* Buffer is now flushed */
    typescript->length = 0;
    typescript->last_flush = this_flush;

}

#ifdef ENABLE_S3

/**
 * Helper struct for receiving response data from libcurl.
 */
typedef struct guac_ts_s3_response {
    char* data;
    size_t size;
} guac_ts_s3_response;

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
 * Uploads a local file to S3 using a single PutObject request.
 *
 * @param endpoint
 *     The S3 endpoint URL.
 *
 * @param bucket
 *     The S3 bucket name.
 *
 * @param key
 *     The S3 object key.
 *
 * @param region
 *     The S3 region.
 *
 * @param access_key
 *     The S3 access key ID.
 *
 * @param secret_key
 *     The S3 secret access key.
 *
 * @param filepath
 *     The local file path to upload.
 *
 * @return
 *     Zero on success, non-zero on failure.
 */
static int guac_ts_s3_upload_file(const char* endpoint, const char* bucket,
        const char* key, const char* region, const char* access_key,
        const char* secret_key, const char* filepath) {

    /* Open and read file into memory */
    FILE* f = fopen(filepath, "rb");
    if (f == NULL)
        return 1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* file_data = NULL;
    if (file_size > 0) {
        file_data = malloc(file_size);
        if (file_data == NULL) {
            fclose(f);
            return 1;
        }
        if (fread(file_data, 1, file_size, f) != (size_t) file_size) {
            free(file_data);
            fclose(f);
            return 1;
        }
    }
    fclose(f);

    /* Build URL and URI */
    char url[4096];
    char uri[2048];
    char host[512];

    snprintf(uri, sizeof(uri), "/%s/%s", bucket, key);
    snprintf(url, sizeof(url), "%s%s", endpoint, uri);
    guac_ts_extract_host(endpoint, host);

    /* Compute payload hash */
    char payload_hash[65];
    guac_ts_sha256_hex(file_data ? file_data : "", file_size > 0 ? file_size : 0,
            payload_hash);

    /* Get current UTC time */
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);

    char date_stamp[16];
    char amz_date[32];
    strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", &tm);
    strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", &tm);

    /* Scope */
    char scope[128];
    snprintf(scope, sizeof(scope), "%s/%s/s3/aws4_request", date_stamp, region);

    /* Canonical headers */
    char canonical_headers[2048];
    snprintf(canonical_headers, sizeof(canonical_headers),
            "content-type:application/octet-stream\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
            host, payload_hash, amz_date);
    const char* signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";

    /* Canonical request */
    char canonical_request[8192];
    snprintf(canonical_request, sizeof(canonical_request),
            "PUT\n%s\n\n%s\n%s\n%s",
            uri, canonical_headers, signed_headers, payload_hash);

    /* Hash canonical request */
    char canonical_request_hash[65];
    guac_ts_sha256_hex(canonical_request, strlen(canonical_request),
            canonical_request_hash);

    /* String to sign */
    char string_to_sign[4096];
    snprintf(string_to_sign, sizeof(string_to_sign),
            "AWS4-HMAC-SHA256\n%s\n%s\n%s",
            amz_date, scope, canonical_request_hash);

    /* Derive signing key */
    unsigned char date_key[32], region_key[32], service_key[32], signing_key[32];
    char key_prefix[256];
    snprintf(key_prefix, sizeof(key_prefix), "AWS4%s", secret_key);
    guac_ts_hmac_sha256(key_prefix, strlen(key_prefix), date_stamp, strlen(date_stamp), date_key);
    guac_ts_hmac_sha256(date_key, 32, region, strlen(region), region_key);
    guac_ts_hmac_sha256(region_key, 32, "s3", 2, service_key);
    guac_ts_hmac_sha256(service_key, 32, "aws4_request", 12, signing_key);

    /* Compute signature */
    unsigned char signature_bytes[32];
    guac_ts_hmac_sha256(signing_key, 32, string_to_sign, strlen(string_to_sign),
            signature_bytes);

    char signature[65];
    for (int i = 0; i < 32; i++)
        sprintf(signature + i * 2, "%02x", signature_bytes[i]);
    signature[64] = '\0';

    /* Build Authorization header */
    char auth_header[1024];
    snprintf(auth_header, sizeof(auth_header),
            "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, "
            "SignedHeaders=%s, Signature=%s",
            access_key, scope, signed_headers, signature);

    /* Build header list */
    char amz_date_header[64];
    snprintf(amz_date_header, sizeof(amz_date_header), "x-amz-date: %s", amz_date);

    char amz_content_sha256[128];
    snprintf(amz_content_sha256, sizeof(amz_content_sha256),
            "x-amz-content-sha256: %s", payload_hash);

    char host_header[1024];
    snprintf(host_header, sizeof(host_header), "Host: %s", host);

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, amz_date_header);
    headers = curl_slist_append(headers, amz_content_sha256);
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    headers = curl_slist_append(headers, host_header);

    /* Perform PUT */
    CURL* curl = curl_easy_init();
    if (curl == NULL) {
        curl_slist_free_all(headers);
        free(file_data);
        return 1;
    }

    guac_ts_s3_response discard = { .data = NULL, .size = 0 };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t) file_size);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, guac_ts_s3_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &discard);

    /* Provide data from memory buffer via read callback */
    if (file_data != NULL && file_size > 0) {
        FILE* upload_file = fopen(filepath, "rb");
        if (upload_file) {
            curl_easy_setopt(curl, CURLOPT_READDATA, upload_file);
        }
    }
    else {
        /* Empty file */
        curl_easy_setopt(curl, CURLOPT_READDATA, NULL);
    }

    CURLcode res = curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(file_data);
    free(discard.data);

    if (res != CURLE_OK || http_code != 200)
        return 1;

    return 0;
}

guac_terminal_typescript* guac_terminal_typescript_alloc_s3(const char* name,
        const char* endpoint, const char* bucket, const char* key,
        const char* region, const char* access_key, const char* secret_key) {

    /* Create temp directory for typescript files */
    char temp_dir[] = "/tmp/guac-typescript-XXXXXX";
    if (mkdtemp(temp_dir) == NULL)
        return NULL;

    /* Allocate typescript using temp dir as path */
    guac_terminal_typescript* typescript =
        guac_terminal_typescript_alloc(temp_dir, name, 0, 1);
    if (typescript == NULL) {
        rmdir(temp_dir);
        return NULL;
    }

    /* Store S3 config for upload on close */
    typescript->use_s3 = 1;

    typescript->s3_endpoint = guac_mem_alloc(strlen(endpoint) + 1);
    strcpy(typescript->s3_endpoint, endpoint);

    typescript->s3_bucket = guac_mem_alloc(strlen(bucket) + 1);
    strcpy(typescript->s3_bucket, bucket);

    typescript->s3_key = guac_mem_alloc(strlen(key) + 1);
    strcpy(typescript->s3_key, key);

    typescript->s3_region = guac_mem_alloc(strlen(region) + 1);
    strcpy(typescript->s3_region, region);

    typescript->s3_access_key = guac_mem_alloc(strlen(access_key) + 1);
    strcpy(typescript->s3_access_key, access_key);

    typescript->s3_secret_key = guac_mem_alloc(strlen(secret_key) + 1);
    strcpy(typescript->s3_secret_key, secret_key);

    typescript->s3_temp_path = guac_mem_alloc(strlen(temp_dir) + 1);
    strcpy(typescript->s3_temp_path, temp_dir);

    return typescript;

}

#endif /* ENABLE_S3 */

void guac_terminal_typescript_free(guac_terminal_typescript* typescript) {

    /* Do nothing if no typescript provided */
    if (typescript == NULL)
        return;

    /* Flush any pending data */
    guac_terminal_typescript_flush(typescript);

    /* Write footer */
    guac_common_write(typescript->data_fd, GUAC_TERMINAL_TYPESCRIPT_FOOTER,
            sizeof(GUAC_TERMINAL_TYPESCRIPT_FOOTER) - 1);

    /* Close file descriptors */
    close(typescript->data_fd);
    close(typescript->timing_fd);

#ifdef ENABLE_S3
    /* Upload to S3 if configured */
    if (typescript->use_s3) {

        /* Build full paths to the temp files */
        char data_path[4096];
        char timing_path[4096];
        snprintf(data_path, sizeof(data_path), "%s/%s",
                typescript->s3_temp_path, typescript->data_filename);
        snprintf(timing_path, sizeof(timing_path), "%s/%s",
                typescript->s3_temp_path, typescript->timing_filename);

        /* Build S3 key for timing file */
        char timing_key[2048];
        snprintf(timing_key, sizeof(timing_key), "%s.timing",
                typescript->s3_key);

        /* Upload data file */
        guac_ts_s3_upload_file(typescript->s3_endpoint, typescript->s3_bucket,
                typescript->s3_key, typescript->s3_region,
                typescript->s3_access_key, typescript->s3_secret_key,
                data_path);

        /* Upload timing file */
        guac_ts_s3_upload_file(typescript->s3_endpoint, typescript->s3_bucket,
                timing_key, typescript->s3_region,
                typescript->s3_access_key, typescript->s3_secret_key,
                timing_path);

        /* Clean up temp files */
        unlink(data_path);
        unlink(timing_path);
        rmdir(typescript->s3_temp_path);

        /* Free S3 config strings */
        guac_mem_free(typescript->s3_endpoint);
        guac_mem_free(typescript->s3_bucket);
        guac_mem_free(typescript->s3_key);
        guac_mem_free(typescript->s3_region);
        guac_mem_free(typescript->s3_access_key);
        guac_mem_free(typescript->s3_secret_key);
        guac_mem_free(typescript->s3_temp_path);
    }
#endif

    /* Free allocated typescript data */
    guac_mem_free(typescript);

}
