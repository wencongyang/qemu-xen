/*
 * Core Definitions for QAPI Visitor implementations
 *
 * Copyright (C) 2012-2016 Red Hat, Inc.
 *
 * Author: Paolo Bonizni <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */
#ifndef QAPI_VISITOR_IMPL_H
#define QAPI_VISITOR_IMPL_H

#include "qapi/error.h"
#include "qapi/visitor.h"

struct Visitor
{
    /* Must be set */
    void (*start_struct)(Visitor *v, const char *name, void **obj,
                         size_t size, Error **errp);
    void (*end_struct)(Visitor *v, Error **errp);

    void (*start_implicit_struct)(Visitor *v, void **obj, size_t size,
                                  Error **errp);
    /* May be NULL */
    void (*end_implicit_struct)(Visitor *v);

    void (*start_list)(Visitor *v, const char *name, Error **errp);
    /* Must be set */
    GenericList *(*next_list)(Visitor *v, GenericList **list);
    /* Must be set */
    void (*end_list)(Visitor *v);

    void (*type_enum)(Visitor *v, const char *name, int *obj,
                      const char *const strings[], Error **errp);
    /* May be NULL; only needed for input visitors. */
    void (*get_next_type)(Visitor *v, const char *name, QType *type,
                          bool promote_int, Error **errp);

    /* Must be set. */
    void (*type_int64)(Visitor *v, const char *name, int64_t *obj,
                       Error **errp);
    /* Must be set. */
    void (*type_uint64)(Visitor *v, const char *name, uint64_t *obj,
                        Error **errp);
    /* Optional; fallback is type_uint64().  */
    void (*type_size)(Visitor *v, const char *name, uint64_t *obj,
                      Error **errp);
    /* Must be set. */
    void (*type_bool)(Visitor *v, const char *name, bool *obj, Error **errp);
    void (*type_str)(Visitor *v, const char *name, char **obj, Error **errp);
    void (*type_number)(Visitor *v, const char *name, double *obj,
                        Error **errp);
    void (*type_any)(Visitor *v, const char *name, QObject **obj,
                     Error **errp);

    /* May be NULL; most useful for input visitors. */
    void (*optional)(Visitor *v, const char *name, bool *present);

    bool (*start_union)(Visitor *v, bool data_present, Error **errp);
};

void input_type_enum(Visitor *v, const char *name, int *obj,
                     const char *const strings[], Error **errp);
void output_type_enum(Visitor *v, const char *name, int *obj,
                      const char *const strings[], Error **errp);

#endif
