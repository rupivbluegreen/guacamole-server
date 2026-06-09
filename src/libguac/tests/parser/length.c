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

#include <CUnit/CUnit.h>
#include <guacamole/parser.h>
#include <guacamole/parser-constants.h>

#include <stdio.h>
#include <string.h>

/**
 * Parses the given NUL-terminated data and returns the parser's final state.
 *
 * The data is offered to guac_parser_append() in a single call the way a socket
 * read delivers a block of bytes, so an entire length field (every digit) is
 * processed within one invocation — the case in which an unbounded length
 * accumulator would overflow. A bounded iteration count guards the test itself
 * against a parser that fails to make progress.
 *
 * The data is copied into a writable buffer first: guac_parser_append() parses
 * in place and writes NUL terminators into the buffer it is given, so the input
 * must be mutable (the real callers pass the parser's own instruction buffer).
 */
static guac_parse_state final_state_of(const char* data) {

    char buffer[256];
    int remaining = (int) strlen(data);
    CU_ASSERT_FATAL(remaining <= (int) sizeof(buffer));
    memcpy(buffer, data, remaining);

    guac_parser* parser = guac_parser_alloc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(parser);

    char* current = buffer;
    int iterations = 0;

    while (remaining > 0
            && parser->state != GUAC_PARSE_COMPLETE
            && parser->state != GUAC_PARSE_ERROR
            && iterations++ < 1024) {

        int parsed = guac_parser_append(parser, (void*) current, remaining);
        if (parsed == 0)
            break;

        current += parsed;
        remaining -= parsed;

    }

    guac_parse_state state = parser->state;
    guac_parser_free(parser);
    return state;

}

/**
 * Verifies that an element length composed of a very long run of digits is
 * rejected as a parse error rather than overflowing the signed length
 * accumulator. A sufficiently long digit run causes signed integer overflow
 * (undefined behavior), which could otherwise wrap to a value that bypasses
 * the maximum-length check.
 */
void test_parser__length_overflow(void) {

    /* 20+ nines overflow a 32-bit int many times over */
    CU_ASSERT_EQUAL(final_state_of("99999999999999999999.x;"),
            GUAC_PARSE_ERROR);

    /* Values just past 32-bit boundaries */
    CU_ASSERT_EQUAL(final_state_of("4294967296.abcd;"), GUAC_PARSE_ERROR);
    CU_ASSERT_EQUAL(final_state_of("2147483648.a;"), GUAC_PARSE_ERROR);

    /* A long run of leading zeros followed by digits must also be bounded */
    CU_ASSERT_EQUAL(
            final_state_of("000000000000000000000000000099999.y;"),
            GUAC_PARSE_ERROR);

}

/**
 * Verifies that any element length exceeding GUAC_INSTRUCTION_MAX_LENGTH is
 * rejected, even when it does not overflow.
 */
void test_parser__length_exceeds_max(void) {

    /* One past the maximum */
    char too_long[32];
    snprintf(too_long, sizeof(too_long), "%d.x;", GUAC_INSTRUCTION_MAX_LENGTH + 1);
    CU_ASSERT_EQUAL(final_state_of(too_long), GUAC_PARSE_ERROR);

    /* Comfortably within the maximum parses as content (not a length error) */
    char ok[32];
    snprintf(ok, sizeof(ok), "%d.", GUAC_INSTRUCTION_MAX_LENGTH);
    guac_parser* parser = guac_parser_alloc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(parser);
    guac_parser_append(parser, ok, (int) strlen(ok));
    CU_ASSERT_NOT_EQUAL(parser->state, GUAC_PARSE_ERROR);
    guac_parser_free(parser);

}

/**
 * Verifies that a representative spread of malformed length fields each
 * terminate in a defined parser state (complete or error) without crashing or
 * stalling.
 */
void test_parser__malformed_lengths(void) {

    static const char* malformed[] = {
        ".x;",            /* no length */
        "-1.x;",          /* leading sign is not a digit */
        "1x.y;",          /* non-digit within length */
        " 1.x;",          /* leading space */
        "1 .x;",          /* trailing space in length */
        "+5.hello;",      /* leading plus */
    };

    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
        guac_parse_state state = final_state_of(malformed[i]);
        CU_ASSERT_TRUE(state == GUAC_PARSE_ERROR || state == GUAC_PARSE_COMPLETE);
    }

}
