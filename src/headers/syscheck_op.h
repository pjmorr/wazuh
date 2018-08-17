/*
 * Shared functions for Syscheck events decoding
 * Copyright (C) 2016 Wazuh Inc.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __SYSCHECK_OP_H
#define __SYSCHECK_OP_H

#include "analysisd/eventinfo.h"

#ifndef WIN32

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#define PATH_SEP '/'

#else

#include "shared.h"
#include "aclapi.h"

#define BUFFER_LEN 1024
#define PATH_SEP '\\'

#endif

/* Fields for rules */
typedef enum sk_syscheck {
    SK_FILE,
    SK_SIZE,
    SK_PERM,
    SK_UID,
    SK_GID,
    SK_MD5,
    SK_SHA1,
    SK_UNAME,
    SK_GNAME,
    SK_INODE,
    SK_SHA256,
    SK_MTIME,
    SK_CHFIELDS,
    SK_USER_ID,
    SK_USER_NAME,
    SK_GROUP_ID,
    SK_GROUP_NAME,
    SK_PROC_NAME,
    SK_AUDIT_ID,
    SK_AUDIT_NAME,
    SK_EFFECTIVE_UID,
    SK_EFFECTIVE_NAME,
    SK_PPID,
    SK_PROC_ID,
    SK_TAG,
    SK_NFIELDS
} sk_syscheck;

typedef struct __sdb {
    char buf[OS_MAXSTR + 1];
    char comment[OS_MAXSTR + 1];

    char size[OS_FLSIZE + 1];
    char perm[OS_FLSIZE + 1];
    char owner[OS_FLSIZE + 1];
    char gowner[OS_FLSIZE + 1];
    char md5[OS_FLSIZE + 1];
    char sha1[OS_FLSIZE + 1];
    char sha256[OS_FLSIZE + 1];
    char mtime[OS_FLSIZE + 1];
    char inode[OS_FLSIZE + 1];

    char agent_cp[MAX_AGENTS + 1][1];
    char *agent_ips[MAX_AGENTS + 1];
    FILE *agent_fps[MAX_AGENTS + 1];

    // Whodata fields
    char user_id[OS_FLSIZE + 1];
    char user_name[OS_FLSIZE + 1];
    char group_id[OS_FLSIZE + 1];
    char group_name[OS_FLSIZE + 1];
    char process_name[OS_FLSIZE + 1];
    char audit_uid[OS_FLSIZE + 1];
    char audit_name[OS_FLSIZE + 1];
    char effective_uid[OS_FLSIZE + 1];
    char effective_name[OS_FLSIZE + 1];
    char ppid[OS_FLSIZE + 1];
    char process_id[OS_FLSIZE + 1];

    int db_err;

    /* Ids for decoder */
    int id1;
    int id2;
    int id3;
    int idn;
    int idd;

    /* Syscheck rule */
    OSDecoderInfo  *syscheck_dec;

    /* File search variables */
    fpos_t init_pos;

} _sdb; /* syscheck db information */

typedef struct sk_sum_wdata {
    char *user_id;
    char *user_name;
    char *group_id;
    char *group_name;
    char *process_name;
    char *audit_uid;
    char *audit_name;
    char *effective_uid;
    char *effective_name;
    char *ppid;
    char *process_id;
} sk_sum_wdata;

/* File sum structure */
typedef struct sk_sum_t {
    char *size;
    int perm;
    char *uid;
    char *gid;
    char *md5;
    char *sha1;
    char *sha256;
    char *uname;
    char *gname;
    long mtime;
    long inode;
    char *tag;
    sk_sum_wdata wdata;
} sk_sum_t;

extern _sdb sdb;

/* Parse c_sum string. Returns 0 if success, 1 when c_sum denotes a deleted file
   or -1 on failure. */
int sk_decode_sum(sk_sum_t *sum, char *c_sum, char *w_sum);

void sk_fill_event(Eventinfo *lf, const char *f_name, const sk_sum_t *sum);

int sk_build_sum(const sk_sum_t * sum, char * output, size_t size);

/* Delete from path to parent all empty folders */
int remove_empty_folders(const char *path);

/* Delete path file and all empty folders above */
int delete_target_file(const char *path);

void sk_sum_clean(sk_sum_t * sum);

int fim_find_child_depth(const char *parent, const char *child);

//Change in Windows paths all slashes for backslashes for compatibility agent<3.4 with manager>=3.4
void normalize_path(char *path);

#ifndef WIN32

const char *get_user(__attribute__((unused)) const char *path, int uid, __attribute__((unused)) char **sid);
const char* get_group(int gid);

#else

const char *get_user(const char *path, __attribute__((unused)) int uid, char **sid);
const char *get_group(__attribute__((unused)) int gid);

#endif

#endif
