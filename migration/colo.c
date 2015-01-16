/*
 * COLO Implementation
 *
 * Copyright Fujitsu, Corp. 2015
 *
 * Authors:
 *     Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu-common.h"
#include "qmp-commands.h"
#include "replication.h"

void qmp_xen_set_replication(bool enable, bool primary,
                                   bool has_failover, bool failover,
                                   Error **errp)
{
    ReplicationMode mode = primary ? REPLICATION_MODE_PRIMARY : REPLICATION_MODE_SECONDARY;

    if (has_failover && enable) {
        error_setg(errp, "Parameter '%s' is only for stopping replication",
                   "failover");
    }

    if (enable) {
        replication_start_all(mode, errp);
    } else {
        replication_stop_all(failover, failover ? NULL : errp);
    }
}

void qmp_xen_get_replication_error(Error **errp)
{
    replication_get_error_all(errp);
}

void qmp_xen_do_checkpoint(Error **errp)
{
    replication_do_checkpoint_all(errp);
}
