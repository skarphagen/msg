/**
 *   Copyright (C) 2021 Skarphagen Embedded
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <msg_tprint.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#define CONCATENATE(x, y) x ## y
#define CONCATENATE_EXPAND(x, y) CONCATENATE(x, y)
#define VAR_NAME(v) CONCATENATE_EXPAND(v, __LINE__)

#define STR_COPY(cpy, str)					\
        size_t VAR_NAME(len) = strlen(str);			\
        char VAR_NAME(buf)[VAR_NAME(len) + 1];			\
        (cpy) = memcpy(VAR_NAME(buf), str, VAR_NAME(len));	\
        (cpy)[VAR_NAME(len)] = 0

/*
 * Reserved characters
 */
#define ROW_DELIM  2
#define FMT_DELIM '%'

/*
 * Adjustment characters
 */
#define FMT_ADJ_LEFT   'l'
#define FMT_ADJ_CENTER 'c'
#define FMT_ADJ_RIGHT  'r'

struct tabular {
        size_t str_len;
        char *str;
        char *row;
        char rowsep;
        char columnsep;
        TAILQ_ENTRY(tabular) entries;
};

struct msg_tprint {
        int str_max;
        int tab_sum;
        int columns;
        char columnsep;
        int *mcw_table;
        FILE *stream;
        void *user;
        void (*func)(void *user, const char *format, va_list ap);
        TAILQ_HEAD(tprint_head, tabular) header;
};

/**
 * Remove character form a string
 */
static char *str_remove(char *str, char remove)
{
        int i, j;

        for (i = 0; str[i]; i++) {
                if (str[i] == remove) {
                        for (j = i; str[j]; j++)
                                str[j] = str[j + 1];
                }
        }
        return str;
}

/**
 * Print function
 */
static void print(struct msg_tprint *tprint, const char *format, ...)
{
        va_list ap;

        if (tprint->func) {
                va_start(ap, format);
                tprint->func(tprint->user, format, ap);
                va_end(ap);
        }
}

/**
 * Default print function
 */
static void tprint_func(void *user, const char *format, va_list ap)
{
        struct msg_tprint *tprint = user;

        vfprintf(tprint->stream, format, ap);
}

/**
 * Strip off any adjustment character from the format string.
 */
static char strip_off_adjustment(char *fmt)
{
        char adjustment;
        size_t len;
        char *adj;

        len = strlen(fmt);
        adj = &fmt[len ? len - 1 : len];
        switch (adj[0]) {
        case FMT_ADJ_RIGHT:
                adj[0] = 0;
                adjustment = FMT_ADJ_RIGHT;
                break;
        case FMT_ADJ_CENTER:
                adj[0] = 0;
                adjustment = FMT_ADJ_CENTER;
                break;
        case FMT_ADJ_LEFT:
                adj[0] = 0;
                adjustment = FMT_ADJ_LEFT;
                break;
        default:
                adjustment = FMT_ADJ_LEFT;
                break;
        }
        return adjustment;
}

/**
 * Get the first format
 */
static char *fmt_first(char *fmt, char **next, char delim)
{
        char *first = NULL;
        char *second = NULL;
        int i;

        if (!fmt)
                return NULL;
        for (i = 0; fmt[i]; i++) {
                if (!first && fmt[i] == delim) {
                        first = &fmt[i];
                } else if (fmt[i] == delim) {
                        second = &fmt[i];
                        break;
                }
        }
        if (second) {
                if (first == second - 1) /* %% */
                        /* search for the next % */
                        for (second++; second[0] && second[0] != delim;
                             second++);
                *next = second[0] ? second + 1 : NULL;
                second[0] = 0;
        } else {
                *next = NULL;
        }
        /*
         * At least 2 characters in a format
         */
        if (first && first[0] && first[1])
                return first;
        if (next)
                (--(*next))[0] = delim;
        return NULL;
}

/**
 * Get the next format.
 */
static char *fmt_next(char **next, char delim)
{
        if (*next)
                (--(*next))[0] = delim;
        return fmt_first(*next, next, delim);
}

/**
 * Reallocate a memory area
 */
static void *trealloc(void *ptr, size_t size)
{
        void *new_ptr;

        new_ptr = realloc(ptr, size);
        if (!new_ptr)
                err(1, NULL);
        return new_ptr;
}

/**
 * Allocate a new tabular and add to the tabular list
 */
static struct tabular *new_tabular(struct msg_tprint *tprint)
{
        struct tabular *tabular;

        tabular = trealloc(NULL, sizeof(*tabular));
        tabular->str_len = 0;
        tabular->str = NULL;
        tabular->row = NULL;
        tabular->rowsep = 0;
        tabular->columnsep = 0;
        TAILQ_INSERT_TAIL(&tprint->header, tabular, entries);
        return tabular;
}

/**
 * Append a string
 */
static size_t str_append(char **str, const char *format, va_list ap)
{
        char *strp = *str;
        char *fmt;
        char adjust;
        size_t asize;
        size_t ssize;
        va_list apc;

        STR_COPY(fmt, format);
        adjust = strip_off_adjustment(fmt);
        ssize = strp ? strlen(strp) : 0;
        if (fmt[1] != FMT_DELIM) {
                va_copy(apc, ap);
                asize = vsnprintf(NULL, 0, fmt, apc);
                va_end(apc);
        } else { /* %% -> empty cell */
                asize = 0;
        }
        strp = trealloc(strp, ssize + asize + 3);
        strp[ssize++] = ROW_DELIM;
        strp[ssize++] = adjust;
        if (fmt[1] != FMT_DELIM) {
                va_copy(apc, ap);
                asize = vsnprintf(&strp[ssize], asize + 1, fmt, apc);
                va_end(apc);
        } else {
                strp[ssize] = 0;
        }
        *str = strp;
        return asize;
}

/**
 * Add a new entry to the max column with table
 */
static void add_mcw_table(struct msg_tprint *tprint, int column)
{
        size_t newsize;

        newsize = (column + 1) * sizeof(*tprint->mcw_table);
        tprint->mcw_table = trealloc(tprint->mcw_table, newsize);
        tprint->mcw_table[column] = 0;
}

/**
 * Set the max width for a column
 */
static void set_max_column_width(struct msg_tprint *tprint, int column, int len)
{
        if (column > tprint->columns) {
                /* A new column */
                tprint->columns = column;
                add_mcw_table(tprint, column);
        }
        /* Set the max lenght for the column */
        tprint->mcw_table[column] = MAX(len, tprint->mcw_table[column]);
}

/**
 * Print column separator
 */
static void tprint_column_sep(struct msg_tprint *tprint, int column)
{
        if (tprint->columnsep) {
                char *fmt;
                if (column == 0)
                        fmt = "%c ";  /* left column */
                else if (column == tprint->columns)
                        fmt = " %c";  /* right column */
                else
                        fmt = " %c ";
                print(tprint, fmt, tprint->columnsep);
        } else if (tprint->columns != column && column != 0) {
                print(tprint, " ");
        }
}

/**
 * Print a row
 */
static void print_row(struct msg_tprint *tprint, struct tabular *tabular)
{
        int adjust, left, right, column;
        char *fmt, *next, *str;
        char delim = ROW_DELIM;

        tprint_column_sep(tprint, 0);
        for (fmt = fmt_first(tabular->row, &next, delim), column = 1; fmt;
             fmt = fmt_next(&next, delim), column++) {
                str = &fmt[2];
                adjust = tprint->mcw_table[column] - strlen(str);
                switch (fmt[1]) {
                case FMT_ADJ_RIGHT:
                        print(tprint, "%*s%s", adjust, "", str);
                        break;
                case FMT_ADJ_CENTER:
                        right = adjust / 2;
                        left = adjust - right;
                        print(tprint, "%*s%s%*s", left, "", str, right, "");
                        break;
                default: /* FMT_ADJ_LEFT */
                        print(tprint, "%s%*s", str, adjust, "");
                        break;
                }
                tprint_column_sep(tprint, column);
        }
        /*
         * Add emtpy cells if any left overs
         */
        for (; column <= tprint->columns; column++) {
                adjust = tprint->mcw_table[column];
                print(tprint, "%*s", adjust, "");
                tprint_column_sep(tprint, column);
        }
}

/**
 * Print a string
 */
static void print_str(struct msg_tprint *tprint, struct tabular *tabular)
{
        int asize, left, right, max;
        char adjust = tabular->str[1];
        char *str = &tabular->str[2];

        if (tprint->columnsep)
                print(tprint, "%c ", tprint->columnsep);
        max = tprint->tab_sum ? tprint->tab_sum : tprint->str_max;
        asize = max - tabular->str_len;
        switch (adjust) {
        case FMT_ADJ_RIGHT:
                print(tprint, "%*s%s", asize, "", str);
                break;
        case FMT_ADJ_CENTER:
                right = asize / 2;
                left = asize - right;
                print(tprint, "%*s%s%*s", left, "", str, right, "");
                break;
        default: /* FMT_ADJ_LEFT */
                print(tprint, "%s%*s", str, asize, "");
                break;
        }
        if (tprint->columnsep)
                print(tprint, " %c", tprint->columnsep);
}

/**
 * Print line separators
 */
static void print_sep(struct msg_tprint *tprint, struct tabular *tabular)
{
        char columnsep, rowsep;
        int column, len;
        char space = ' ';

        columnsep = tabular->columnsep ? tabular->columnsep : space;
        rowsep = tabular->rowsep ? tabular->rowsep : space;
	if (tprint->columnsep)
		print(tprint, "%c", columnsep);
        for (column = 1; column <= tprint->columns; column++) {
                len = tprint->mcw_table[column];
                len += tprint->columnsep ? 2 : 0;
                while (len-- > 0)
                        print(tprint, "%c", rowsep);
		if (column != tprint->columns)
			print(tprint, "%c", columnsep);
		else if (tprint->columnsep)
			print(tprint, "%c", columnsep);
        }
        if (!tprint->columns) {
                len = tprint->str_max;
                len += tprint->columnsep ? 2 : -2;
                while (len-- > 0)
                        print(tprint, "%c", rowsep);
		if (tprint->columnsep)
			print(tprint, "%c", columnsep);
        }
}

/**
 * Summarize all columns
 */
static int tabular_column_sum(struct msg_tprint *tprint)
{
        int column;
        int sum;

        /*
         * Sum of all columns
         */
        for (sum = 0, column = 0; column <= tprint->columns; column++)
                sum += tprint->mcw_table[column];
        /*
         * Add column separator, skip the outer frames
         * 3 -> " c "
         * 1 -> " "
         */
        for (column = 1; column < tprint->columns; column++)
                sum += tprint->columnsep ? 3 : 1;
        return sum;
}

/**
 * Adjust column width prior to the string length
 */
static void adjust_column_width(struct msg_tprint *tprint)
{
        int column;
        int diff;

        if (tprint->columns) {
                tprint->tab_sum = tabular_column_sum(tprint);
                diff = tprint->tab_sum - tprint->str_max;
                /*
                 * Extend max column width, start from the right one
                 */
                while (diff <= 0) {
                        for (column = tprint->columns; diff <= 0 && column > 0;
                             column--, diff++) {
                                tprint->mcw_table[column]++;
                                tprint->tab_sum++;
                        }
                }
        }
}

/**
 * Create a tprint interface handle
 */
void msg_tprint_init(struct msg_tprint **tprint, char columnsep)
{
        struct msg_tprint *tprintp;

        tprintp = trealloc(NULL, sizeof(*tprintp));
        tprintp->str_max = 0;
        tprintp->tab_sum = 0;
        tprintp->columns = 0;
        tprintp->columnsep = columnsep;
        tprintp->mcw_table = NULL;
        tprintp->stream = NULL;
        tprintp->user = tprintp;
        tprintp->func = tprint_func;
        TAILQ_INIT(&tprintp->header);
        add_mcw_table(tprintp, 0);
        *tprint = tprintp;
}

/**
 * Print a row
 */
void msg_tprint_row(struct msg_tprint *tprint, const char *format, ...)
{
        char *fmt, *next, *copy;
        struct tabular *tabular;
        char delim = FMT_DELIM;
        va_list ap;
        size_t len;
        int column;

        STR_COPY(copy, format);
        copy = str_remove(copy, ' ');
        tabular = new_tabular(tprint);
        va_start(ap, format);
        for (fmt = fmt_first(copy, &next, delim), column = 1; fmt;
             fmt = fmt_next(&next, delim), column++) {
                len = str_append(&tabular->row, fmt, ap);
                if (fmt[1] != delim)
			(void)va_arg(ap, int);
                /* else %% -> empty cell */
                set_max_column_width(tprint, column, len);
        }
        va_end(ap);
}

/**
 * Print a string without column separation.
 */
void msg_tprint_str(struct msg_tprint *tprint, const char *format, ...)
{
        struct tabular *tabular;
        va_list ap;

        tabular = new_tabular(tprint);
        va_start(ap, format);
        tabular->str_len = str_append(&tabular->str, format, ap);
        va_end(ap);
        tprint->str_max = MAX(tabular->str_len, tprint->str_max);
}

/**
 * Print separators
 */
void msg_tprint_sep(struct msg_tprint *tprint, char rowsep, char columnsep)
{
        struct tabular *tabular;

        tabular = new_tabular(tprint);
        tabular->rowsep = rowsep;
        tabular->columnsep = columnsep;
}

/**
 * Do the tabular printing
 */
void msg_tprint_do(struct msg_tprint *tprint, FILE *stream)
{
        struct tabular *tabular;

        tprint->stream = stream ? stream : stdout;
        adjust_column_width(tprint);
        TAILQ_FOREACH(tabular, &tprint->header, entries) {
                if (tabular->row)
                        print_row(tprint, tabular);
                else if (tabular->str)
                        print_str(tprint, tabular);
                else
                        print_sep(tprint, tabular);
                print(tprint, "\n");
        }
}

/**
 * Set tprint callback function
 */
void msg_tprint_cb(struct msg_tprint *tprint,
		   void (*func)(void *user, const char *format, va_list ap),
		   void *user)
{
        tprint->user = user;
        tprint->func = func;
}

/**
 * Cleanup
 */
void msg_tprint_exit(struct msg_tprint *tprint)
{
        struct tabular *tabular;

        while (!TAILQ_EMPTY(&tprint->header)) {
                tabular = TAILQ_FIRST(&tprint->header);
                TAILQ_REMOVE(&tprint->header, tabular, entries);
                free(tabular->row);
                free(tabular->str);
                free(tabular);
        }
        free(tprint->mcw_table);
        free(tprint);
}
