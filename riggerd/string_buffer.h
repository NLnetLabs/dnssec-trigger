#include "config.h"

#if !defined STRING_BUFFER_H && defined FWD_ZONES_SUPPORT
#define STRING_BUFFER_H

#include <stdlib.h>

/**
 * Just a fat pointer wrapping char pointer
 */
struct string_buffer {
    /** String itself */
    char* string;
    /** Length of the string buffer */
    size_t length;
};

#define string_builder(STR)  \
{                            \
    .string = (STR),         \
    .length = sizeof((STR)), \
}

#endif /* STRING_BUFFER_H */

