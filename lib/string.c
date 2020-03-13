/*
 * Copyright (c) 2009, 2011, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <ctype.h>
#include <string.h>

#include "util.h"

#ifndef HAVE_STRNLEN
size_t
strnlen(const char *s, size_t maxlen)
{
    const char *end = memchr(s, '\0', maxlen);
    return end ? end - s : maxlen;
}
#endif

#ifdef _WIN32
char *strcasestr(const char *str, const char *substr)
{
    do {
        for (size_t i = 0; ; i++) {
            if (!substr[i]) {
                return CONST_CAST(char *, str);
            } else if (tolower(substr[i]) != tolower(str[i])) {
                break;
            }
        }
    } while (*str++);
    return NULL;
}
#endif

/* Expect string 'd' is atleast three char longer than 's'. */
char *
str_quotify(const char *s, int len, char *d)
{
    bool found_space = false;
    int i = 0;

    d[0] = '"';
    while(s[i] != '\0' && i <= len) {
        d[i + 1] = s[i];
        if (s[i] == ' ') {
            found_space = true;
        }
        i++;
    }
    if (found_space) {
        d[i + 1] = '"';
        d[i + 2] = '\0';
        return d;
    } else {
        return &d[1];
    }
}
