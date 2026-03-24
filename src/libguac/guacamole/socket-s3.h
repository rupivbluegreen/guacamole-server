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

#ifndef GUAC_SOCKET_S3_H
#define GUAC_SOCKET_S3_H

/**
 * Provides a guac_socket implementation that writes data to an S3-compatible
 * object store (such as MinIO) using multipart upload via libcurl.
 *
 * @file socket-s3.h
 */

#include "guacamole/socket.h"

/**
 * The minimum size of a single S3 multipart upload part, in bytes. S3 requires
 * all parts except the last to be at least 5 MB.
 */
#define GUAC_SOCKET_S3_MIN_PART_SIZE (5 * 1024 * 1024)

/**
 * The maximum number of parts allowed in an S3 multipart upload.
 */
#define GUAC_SOCKET_S3_MAX_PARTS 10000

/**
 * Allocates and initializes a new guac_socket which writes all data to an
 * S3-compatible object store using multipart upload. The upload is initiated
 * immediately, parts are uploaded as the internal buffer fills, and the
 * upload is completed (or aborted on error) when the socket is freed.
 *
 * This socket is write-only. Attempts to read from it will fail.
 *
 * @param endpoint
 *     The S3 endpoint URL (e.g., "http://minio:9000").
 *
 * @param bucket
 *     The S3 bucket name.
 *
 * @param key
 *     The S3 object key (path within the bucket).
 *
 * @param region
 *     The S3 region (e.g., "us-east-1").
 *
 * @param access_key
 *     The S3 access key ID.
 *
 * @param secret_key
 *     The S3 secret access key.
 *
 * @param use_ssl
 *     Non-zero if the endpoint uses HTTPS, zero for HTTP.
 *
 * @return
 *     A newly allocated guac_socket which writes to the specified S3
 *     destination, or NULL if an error occurs.
 */
guac_socket* guac_socket_open_s3(const char* endpoint, const char* bucket,
        const char* key, const char* region, const char* access_key,
        const char* secret_key, int use_ssl);

#endif
