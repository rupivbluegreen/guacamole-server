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

#define _POSIX_C_SOURCE 200809L

#include "common/iconv.h"

#include <CUnit/CUnit.h>

#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * The complete set of guac_iconv readers, including the newline-normalizing
 * variants. The normalizing single-byte readers (CP1252, ISO 8859-1, MacRoman)
 * are of particular interest: their CRLF peek-ahead invokes the underlying
 * reader with zero bytes remaining when a bare '\r' ends the input, which must
 * not result in a read past the end of the buffer.
 */
static guac_iconv_read* const all_readers[] = {
    GUAC_READ_UTF8,             GUAC_READ_UTF16,
    GUAC_READ_CP1252,           GUAC_READ_ISO8859_1,
    GUAC_READ_MACROMAN,
    GUAC_READ_UTF8_NORMALIZED,  GUAC_READ_UTF16_NORMALIZED,
    GUAC_READ_CP1252_NORMALIZED,GUAC_READ_ISO8859_1_NORMALIZED,
    GUAC_READ_MACROMAN_NORMALIZED,
};

static const int NUM_READERS = sizeof(all_readers) / sizeof(all_readers[0]);

/**
 * The complete set of guac_iconv writers, including the CRLF variants which
 * expand a single '\n' codepoint into the two-byte sequence "\r\n" (or four
 * bytes for UTF-16) and so are most likely to overrun a tight output limit.
 */
static guac_iconv_write* const all_writers[] = {
    GUAC_WRITE_UTF8,            GUAC_WRITE_UTF16,
    GUAC_WRITE_CP1252,          GUAC_WRITE_ISO8859_1,
    GUAC_WRITE_MACROMAN,
    GUAC_WRITE_UTF8_CRLF,       GUAC_WRITE_UTF16_CRLF,
    GUAC_WRITE_CP1252_CRLF,     GUAC_WRITE_ISO8859_1_CRLF,
    GUAC_WRITE_MACROMAN_CRLF,
};

static const int NUM_WRITERS = sizeof(all_writers) / sizeof(all_writers[0]);

/**
 * Runs the given statement within a forked child process, asserting that the
 * child terminates normally (i.e. does NOT die from a signal such as SIGSEGV).
 * The guarded conversion helpers below position their buffers flush against an
 * inaccessible guard page, so any read or write one byte past the permitted
 * region faults — turning an out-of-bounds access into a clean test failure
 * instead of silent memory corruption.
 */
#define ASSERT_NO_FAULT(stmt)                                                 \
    do {                                                                      \
        pid_t _child = fork();                                                \
        CU_ASSERT_NOT_EQUAL_FATAL(_child, -1);                                \
        if (_child == 0) {                                                    \
            do { stmt; } while (0);                                           \
            _exit(0);                                                         \
        }                                                                     \
        int _status = 0;                                                      \
        CU_ASSERT_EQUAL_FATAL(waitpid(_child, &_status, 0), _child);          \
        if (WIFSIGNALED(_status)) {                                           \
            CU_FAIL("conversion accessed memory out of bounds: " #stmt);      \
        }                                                                     \
        else {                                                                \
            CU_ASSERT_EQUAL(WEXITSTATUS(_status), 0);                         \
        }                                                                     \
    } while (0)

/**
 * Allocates a region of exactly the given size whose final byte is immediately
 * followed by an inaccessible guard page. Reading or writing past the region
 * faults with SIGSEGV. Returns NULL on failure.
 */
static char* guarded_region(int size, void** mapping, size_t* mapping_size) {

    long page = sysconf(_SC_PAGESIZE);
    size_t data_bytes = (size > 0) ? (size_t) size : 1;

    /* One or more data pages, plus a single trailing guard page */
    size_t span = ((data_bytes + page - 1) / page) * page + page;

    char* base = mmap(NULL, span, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return NULL;

    /* Make the final page inaccessible */
    if (mprotect(base + span - page, page, PROT_NONE) != 0) {
        munmap(base, span);
        return NULL;
    }

    *mapping = base;
    *mapping_size = span;

    /* Position the region so its last byte abuts the guard page */
    return base + (span - page) - data_bytes;

}

/**
 * Converts the given input using a reader/writer pair, with the INPUT buffer
 * positioned flush against a guard page. Any read past in_size faults.
 */
static void convert_guarded_input(guac_iconv_read* reader,
        guac_iconv_write* writer, const unsigned char* in, int in_size) {

    void* mapping;
    size_t mapping_size;
    char* input = guarded_region(in_size, &mapping, &mapping_size);
    if (input == NULL)
        _exit(2);

    if (in_size > 0)
        memcpy(input, in, in_size);

    char output[512];
    const char* in_ptr = input;
    char* out_ptr = output;

    guac_iconv(reader, &in_ptr, in_size, writer, &out_ptr, sizeof(output));

    munmap(mapping, mapping_size);

}

/**
 * Converts the given input using a reader/writer pair, with the OUTPUT buffer
 * positioned flush against a guard page and limited to out_size bytes. Any
 * write past out_size faults.
 */
static void convert_guarded_output(guac_iconv_read* reader,
        guac_iconv_write* writer, const unsigned char* in, int in_size,
        int out_size) {

    void* mapping;
    size_t mapping_size;
    char* output = guarded_region(out_size, &mapping, &mapping_size);
    if (output == NULL)
        _exit(2);

    char input[64];
    memcpy(input, in, in_size);

    const char* in_ptr = input;
    char* out_ptr = output;

    guac_iconv(reader, &in_ptr, in_size, writer, &out_ptr, out_size);

    munmap(mapping, mapping_size);

}

/**
 * Verifies that a bare trailing carriage return ('\r') at the very end of the
 * input never causes a read past the end of the input buffer, for any reader.
 *
 * This is a regression test for an out-of-bounds read in the normalizing
 * single-byte readers (CP1252, ISO 8859-1, MacRoman): their CRLF peek-ahead
 * invoked the underlying reader with zero bytes remaining, and those readers
 * dereferenced the input pointer without checking the remaining length —
 * reading one byte beyond the buffer. Reachable from a remote RDP server via
 * the CLIPRDR clipboard channel when newline normalization is enabled.
 */
void test_iconv_bounds__trailing_cr(void) {

    const unsigned char input[] = { '\r' };

    for (int i = 0; i < NUM_READERS; i++)
        ASSERT_NO_FAULT(convert_guarded_input(all_readers[i],
                    GUAC_WRITE_UTF8, input, sizeof(input)));

    /* Also exercise a longer input whose final byte is a bare CR */
    const unsigned char trailing[] = { 'a', 'b', 'c', '\r' };
    for (int i = 0; i < NUM_READERS; i++)
        ASSERT_NO_FAULT(convert_guarded_input(all_readers[i],
                    GUAC_WRITE_UTF8, trailing, sizeof(trailing)));

}

/**
 * Verifies that truncated multi-byte sequences and lone high bytes at the end
 * of the input never cause a read past the end of the input buffer, for any
 * reader.
 */
void test_iconv_bounds__truncated_input(void) {

    /* Truncated UTF-8 lead bytes, a lone UTF-16 byte, and high single-byte
     * values, each placed so the sequence ends exactly at the guard page */
    static const unsigned char two_byte[]   = { 0xC3 };        /* UTF-8 lead, missing cont. */
    static const unsigned char three_byte[] = { 0xE2, 0x82 };  /* UTF-8 lead + 1 of 2 cont. */
    static const unsigned char four_byte[]  = { 0xF0, 0x9F, 0x98 }; /* UTF-8 lead + 2 of 3 */
    static const unsigned char odd_utf16[]  = { 0x41 };        /* single byte for UTF-16 */
    static const unsigned char high_byte[]  = { 0xFF };        /* high single-byte value */

    const unsigned char* inputs[] = {
        two_byte, three_byte, four_byte, odd_utf16, high_byte
    };
    int sizes[] = {
        sizeof(two_byte), sizeof(three_byte), sizeof(four_byte),
        sizeof(odd_utf16), sizeof(high_byte)
    };

    for (int s = 0; s < 5; s++)
        for (int i = 0; i < NUM_READERS; i++)
            ASSERT_NO_FAULT(convert_guarded_input(all_readers[i],
                        GUAC_WRITE_UTF8, inputs[s], sizes[s]));

    /* Empty input must also be safe for every reader */
    for (int i = 0; i < NUM_READERS; i++)
        ASSERT_NO_FAULT(convert_guarded_input(all_readers[i],
                    GUAC_WRITE_UTF8, (const unsigned char*) "", 0));

}

/**
 * Verifies that converting a newline into a tight output buffer never writes
 * past the output limit, for any writer. The CRLF writers expand '\n' to
 * "\r\n" (two bytes, or four for UTF-16), which is the case most likely to
 * overrun a one- or two-byte output capacity.
 */
void test_iconv_bounds__newline_output(void) {

    const unsigned char newline[] = { '\n' };

    for (int out_size = 0; out_size <= 4; out_size++)
        for (int w = 0; w < NUM_WRITERS; w++)
            ASSERT_NO_FAULT(convert_guarded_output(GUAC_READ_UTF8,
                        all_writers[w], newline, sizeof(newline), out_size));

}

/**
 * Exercises a single reader/writer pair across a spread of representative input
 * bytes and every tiny output capacity (0 through 4 bytes), with the output
 * buffer guarded. Intended to run within a forked child: any out-of-bounds
 * write faults and terminates the child.
 */
static void matrix_child(guac_iconv_read* reader, guac_iconv_write* writer) {

    /* ASCII, CR, LF, CP1252 exception range, and high bytes */
    static const unsigned char bytes[] = { 0x00, 'A', '\r', '\n', 0x80, 0x9F, 0xE9, 0xFF };

    for (size_t b = 0; b < sizeof(bytes); b++) {
        unsigned char input[1] = { bytes[b] };
        for (int out_size = 0; out_size <= 4; out_size++)
            convert_guarded_output(reader, writer, input, 1, out_size);
    }

}

/**
 * Verifies that for every reader/writer combination, converting a single input
 * byte into output buffers of every tiny capacity (0 through 4 bytes) never
 * writes past the output limit. One child process is forked per reader/writer
 * pair (each looping over all byte/size cases) to keep the fork count modest.
 */
void test_iconv_bounds__tiny_buffers_matrix(void) {

    for (int r = 0; r < NUM_READERS; r++)
        for (int w = 0; w < NUM_WRITERS; w++)
            ASSERT_NO_FAULT(matrix_child(all_readers[r], all_writers[w]));

}
