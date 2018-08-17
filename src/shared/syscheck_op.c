/*
 * Shared functions for Syscheck events decoding
 * Copyright (C) 2016 Wazuh Inc.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscheck_op.h"

#ifdef WIN32
#include <sddl.h>
#endif

/* Local variables */
_sdb sdb;

static char *unescape_whodata_sum(char *sum);

/* Parse c_sum string. Returns 0 if success, 1 when c_sum denotes a deleted file
   or -1 on failure. */
int sk_decode_sum(sk_sum_t *sum, char *c_sum, char *w_sum) {
    char *c_perm;
    char *c_mtime;
    char *c_inode;
    char *tag;
    int retval = 0;

    memset(sum, 0, sizeof(sk_sum_t));

    if (c_sum[0] == '-' && c_sum[1] == '1') {
        retval = 1;
    } else {
        sum->size = c_sum;

        if (!(c_perm = strchr(c_sum, ':')))
            return -1;

        *(c_perm++) = '\0';

        if (!(sum->uid = strchr(c_perm, ':')))
            return -1;

        *(sum->uid++) = '\0';
        sum->perm = atoi(c_perm);

        if (!(sum->gid = strchr(sum->uid, ':')))
            return -1;

        *(sum->gid++) = '\0';

        if (!(sum->md5 = strchr(sum->gid, ':')))
            return -1;

        *(sum->md5++) = '\0';

        if (!(sum->sha1 = strchr(sum->md5, ':')))
            return -1;

        *(sum->sha1++) = '\0';

        // New fields: user name, group name, modification time and inode

        if ((sum->uname = strchr(sum->sha1, ':'))) {
            *(sum->uname++) = '\0';

            if (!(sum->gname = strchr(sum->uname, ':')))
                return -1;

            *(sum->gname++) = '\0';

            if (!(c_mtime = strchr(sum->gname, ':')))
                return -1;

            *(c_mtime++) = '\0';

            if (!(c_inode = strchr(c_mtime, ':')))
                return -1;

            *(c_inode++) = '\0';

            sum->sha256 = NULL;

            if ((sum->sha256 = strchr(c_inode, ':')))
                *(sum->sha256++) = '\0';

            /* Look for a defined tag */
            if (tag = strchr(sum->sha256, ':'), tag) {
                *(tag++) = '\0';
                sum->tag = tag;
            }

            sum->mtime = atol(c_mtime);
            sum->inode = atol(c_inode);
        }
    }

    // Get extra data wdata+tags(optional)
    if (w_sum) {
        sum->wdata.user_id = w_sum;

        if ((sum->wdata.user_name = wstr_chr(w_sum, ':'))) {
            *(sum->wdata.user_name++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.group_id = wstr_chr(sum->wdata.user_name, ':'))) {
            *(sum->wdata.group_id++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.group_name = wstr_chr(sum->wdata.group_id, ':'))) {
            *(sum->wdata.group_name++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.process_name = wstr_chr(sum->wdata.group_name, ':'))) {
            *(sum->wdata.process_name++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.audit_uid = wstr_chr(sum->wdata.process_name, ':'))) {
            *(sum->wdata.audit_uid++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.audit_name = wstr_chr(sum->wdata.audit_uid, ':'))) {
            *(sum->wdata.audit_name++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.effective_uid = wstr_chr(sum->wdata.audit_name, ':'))) {
            *(sum->wdata.effective_uid++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.effective_name = wstr_chr(sum->wdata.effective_uid, ':'))) {
            *(sum->wdata.effective_name++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.ppid = wstr_chr(sum->wdata.effective_name, ':'))) {
            *(sum->wdata.ppid++) = '\0';
        } else {
            return -1;
        }

        if ((sum->wdata.process_id = wstr_chr(sum->wdata.ppid, ':'))) {
            *(sum->wdata.process_id++) = '\0';
        } else {
            return -1;
        }

        /* Look for a defined tag */
        if (sum->tag = wstr_chr(sum->wdata.process_id, ':'), sum->tag) {
            *(sum->tag++) = '\0';
        } else {
            sum->tag = NULL;
        }

        sum->wdata.user_name = unescape_whodata_sum(sum->wdata.user_name);
        sum->wdata.process_name = unescape_whodata_sum(sum->wdata.process_name);
        if (*sum->wdata.ppid == '-') {
            sum->wdata.ppid = NULL;
        }
    }

    return retval;
}

char *unescape_whodata_sum(char *sum) {
    char *esc_it;

    if (*sum != '\0' ) {
        // The parameter string is not released
        esc_it = wstr_replace(sum, "\\ ", " ");
        sum = wstr_replace(esc_it, "\\:", ":");
        free(esc_it);
        return sum;
    }
    return NULL;
}

void sk_fill_event(Eventinfo *lf, const char *f_name, const sk_sum_t *sum) {
    int i;

    os_strdup(f_name, lf->filename);
    os_strdup(f_name, lf->fields[SK_FILE].value);

    if (sum->size) {
        os_strdup(sum->size, lf->size_after);
        os_strdup(sum->size, lf->fields[SK_SIZE].value);
    }

    if (sum->perm) {
        lf->perm_after = sum->perm;
        os_calloc(7, sizeof(char), lf->fields[SK_PERM].value);
        snprintf(lf->fields[SK_PERM].value, 7, "%06o", sum->perm);
    }

    if (sum->uid) {
        os_strdup(sum->uid, lf->owner_after);
        os_strdup(sum->uid, lf->fields[SK_UID].value);
    }

    if (sum->gid) {
        os_strdup(sum->gid, lf->gowner_after);
        os_strdup(sum->gid, lf->fields[SK_GID].value);
    }

    if (sum->md5) {
        os_strdup(sum->md5, lf->md5_after);
        os_strdup(sum->md5, lf->fields[SK_MD5].value);
    }

    if (sum->sha1) {
        os_strdup(sum->sha1, lf->sha1_after);
        os_strdup(sum->sha1, lf->fields[SK_SHA1].value);
    }

    if (sum->uname) {
        os_strdup(sum->uname, lf->uname_after);
        os_strdup(sum->uname, lf->fields[SK_UNAME].value);
    }

    if (sum->gname) {
        os_strdup(sum->gname, lf->gname_after);
        os_strdup(sum->gname, lf->fields[SK_GNAME].value);
    }

    if (sum->mtime) {
        lf->mtime_after = sum->mtime;
        os_calloc(20, sizeof(char), lf->fields[SK_MTIME].value);
        snprintf(lf->fields[SK_MTIME].value, 20, "%ld", sum->mtime);
    }

    if (sum->inode) {
        lf->inode_after = sum->inode;
        os_calloc(20, sizeof(char), lf->fields[SK_INODE].value);
        snprintf(lf->fields[SK_INODE].value, 20, "%ld", sum->inode);
    }

    if(sum->sha256) {
        os_strdup(sum->sha256, lf->sha256_after);
        os_strdup(sum->sha256, lf->fields[SK_SHA256].value);
    }

    if(sum->wdata.user_id) {
        os_strdup(sum->wdata.user_id, lf->user_id);
        os_strdup(sum->wdata.user_id, lf->fields[SK_USER_ID].value);
    }

    if(sum->wdata.user_name) {
        os_strdup(sum->wdata.user_name, lf->user_name);
        os_strdup(sum->wdata.user_name, lf->fields[SK_USER_NAME].value);
    }

    if(sum->wdata.group_id) {
        os_strdup(sum->wdata.group_id, lf->group_id);
        os_strdup(sum->wdata.group_id, lf->fields[SK_GROUP_ID].value);
    }

    if(sum->wdata.group_name) {
        os_strdup(sum->wdata.group_name, lf->group_name);
        os_strdup(sum->wdata.group_name, lf->fields[SK_GROUP_NAME].value);
    }

    if(sum->wdata.process_name) {
        os_strdup(sum->wdata.process_name, lf->process_name);
        os_strdup(sum->wdata.process_name, lf->fields[SK_PROC_NAME].value);
    }

    if(sum->wdata.audit_uid) {
        os_strdup(sum->wdata.audit_uid, lf->audit_uid);
        os_strdup(sum->wdata.audit_uid, lf->fields[SK_AUDIT_ID].value);
    }

    if(sum->wdata.audit_name) {
        os_strdup(sum->wdata.audit_name, lf->audit_name);
        os_strdup(sum->wdata.audit_name, lf->fields[SK_AUDIT_NAME].value);
    }

    if(sum->wdata.effective_uid) {
        os_strdup(sum->wdata.effective_uid, lf->effective_uid);
        os_strdup(sum->wdata.effective_uid, lf->fields[SK_EFFECTIVE_UID].value);
    }

    if(sum->wdata.effective_name) {
        os_strdup(sum->wdata.effective_name, lf->effective_name);
        os_strdup(sum->wdata.effective_name, lf->fields[SK_EFFECTIVE_NAME].value);
    }

    if(sum->wdata.ppid) {
        os_strdup(sum->wdata.ppid, lf->ppid);
        os_strdup(sum->wdata.ppid, lf->fields[SK_PPID].value);
    }

    if(sum->wdata.process_id) {
        os_strdup(sum->wdata.process_id, lf->process_id);
        os_strdup(sum->wdata.process_id, lf->fields[SK_PROC_ID].value);
    }

    if(sum->tag) {
        os_strdup(sum->tag, lf->sk_tag);
        os_strdup(sum->tag, lf->fields[SK_TAG].value);
    }

    /* Fields */

    lf->nfields = SK_NFIELDS;

    for (i = 0; i < SK_NFIELDS; i++)
        os_strdup(sdb.syscheck_dec->fields[i], lf->fields[i].key);
}

int sk_build_sum(const sk_sum_t * sum, char * output, size_t size) {
    int r;

    if (sum->uname || sum->gname || sum->mtime || sum->inode) {
        r = snprintf(output, size, "%s:%d:%s:%s:%s:%s:%s:%s:%ld:%ld", sum->size, sum->perm, sum->uid, sum->gid, sum->md5, sum->sha1, sum->uname, sum->gname, sum->mtime, sum->inode);
    } else {
        r = snprintf(output, size, "%s:%d:%s:%s:%s:%s", sum->size, sum->perm, sum->uid, sum->gid, sum->md5, sum->sha1);
    }

    return r < (int)size ? 0 : -1;
}

int remove_empty_folders(const char *path) {
    const char LOCALDIR[] = { PATH_SEP, 'l', 'o', 'c', 'a', 'l', '\0' };
    const char *c;
    char parent[PATH_MAX] = "\0";
    char ** subdir;
    int retval = 0;

    // Get parent
    c = strrchr(path, PATH_SEP);
    if (c) {
        memcpy(parent, path, c - path);
        parent[c - path] = '\0';
        // Don't delete above /local
        if (c = strrchr(parent, PATH_SEP), c && strcmp(c, LOCALDIR) != 0) {
            subdir = wreaddir(parent);
            if (!(subdir && *subdir)) {
                // Remove empty folder
                mdebug1("Removing empty directory '%s'.", parent);
                if (rmdir_ex(parent) != 0) {
                    mwarn("Empty directory '%s' couldn't be deleted. ('%s')",
                        parent, strerror(errno));
                    retval = 1;
                } else {
                    // Get parent and remove it if it's empty
                    retval = remove_empty_folders(parent);
                }
            }

            free_strarray(subdir);
        }
    }

    return retval;
}

int delete_target_file(const char *path) {
    char full_path[PATH_MAX] = "\0";
    snprintf(full_path, PATH_MAX, "%s%clocal", DIFF_DIR_PATH, PATH_SEP);

#ifdef WIN32
    char *windows_path = strchr(path, ':');
    strncat(full_path, (windows_path + 1), PATH_MAX - strlen(full_path) - 1);
#else
    strncat(full_path, path, PATH_MAX - strlen(full_path) - 1);
#endif
    if(rmdir_ex(full_path) == 0){
        mdebug1("Deleting last-entry of file '%s'", full_path);
        return(remove_empty_folders(full_path));
    }
    return 1;
}

void sk_sum_clean(sk_sum_t * sum) {
    free(sum->wdata.user_name);
    free(sum->wdata.process_name);
}

int fim_find_child_depth(const char *parent, const char *child) {

    int length_A = strlen(parent);
    int length_B = strlen(child);

    char* p_first = strdup(parent);
    char *p_second = strdup(child);

    char *diff_str;

    if(parent[length_A - 1] == PATH_SEP){
        p_first[length_A - 1] = '\0';
    }

    if(child[length_B - 1] == PATH_SEP){
        p_second[length_B - 1] = '\0';
    }

    if(strncmp(parent, child, length_A) == 0){
        diff_str = p_second;
        diff_str += length_A;
    }
    else if(strncmp(child, parent, length_B) == 0) {
        diff_str = p_first;
        diff_str += length_B;
    }
    else{
        free(p_first);
        free(p_second);
        return INT_MAX;
    }

    char *c;
    int child_depth = 0;
    c = strchr(diff_str, PATH_SEP);
    while (c != NULL) {
        child_depth++;
        c = strchr(c + 1, PATH_SEP);
    }

    free(p_first);
    free(p_second);
    return child_depth;
}

void normalize_path(char * path) {
    char *ptname = path;

    if(ptname[1] == ':' && ((ptname[0] >= 'A' && ptname[0] <= 'Z') || (ptname[0] >= 'a' && ptname[0] <= 'z'))) {
        /* Change forward slashes to backslashes on entry */
        ptname = strchr(ptname, '/');
        while (ptname) {
            *ptname = '\\';
            ptname++;

            ptname = strchr(ptname, '/');
        }
    }
}

#ifndef WIN32

const char *get_user(__attribute__((unused)) const char *path, int uid, __attribute__((unused)) char **sid) {
    struct passwd *user = getpwuid(uid);
    return user ? user->pw_name : "";
}

const char* get_group(int gid) {
    struct group *group = getgrgid(gid);
    return group ? group->gr_name : "";
}

#else

const char *get_user(const char *path, __attribute__((unused)) int uid, char **sid)
{
    DWORD dwRtnCode = 0;
    PSID pSidOwner = NULL;
    BOOL bRtnBool = TRUE;
    static char AcctName[BUFFER_LEN];
    char DomainName[BUFFER_LEN];
    DWORD dwAcctName = BUFFER_LEN;
    DWORD dwDomainName = BUFFER_LEN;
    SID_NAME_USE eUse = SidTypeUnknown;
    HANDLE hFile;
    PSECURITY_DESCRIPTOR pSD = NULL;

    // Get the handle of the file object.
    hFile = CreateFile(
                       TEXT(path),
                       GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

    // Check GetLastError for CreateFile error code.
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD dwErrorCode = GetLastError();
        LPSTR messageBuffer = NULL;
        LPSTR end;

        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwErrorCode, 0, (LPTSTR) &messageBuffer, 0, NULL);

        if (end = strchr(messageBuffer, '\r'), end) {
            *end = '\0';
        }

        switch (dwErrorCode) {
        case ERROR_ACCESS_DENIED:     // 5
        case ERROR_SHARING_VIOLATION: // 32
            mdebug1("At get_user(%s): CreateFile(): %s (%lu)", path, messageBuffer, dwErrorCode);
            break;
        default:
            mwarn("At get_user(%s): CreateFile(): %s (%lu)", path, messageBuffer, dwErrorCode);
        }

        LocalFree(messageBuffer);
        *AcctName = '\0';
        goto end;
    }

    // Get the owner SID of the file.
    dwRtnCode = GetSecurityInfo(
                                hFile,
                                SE_FILE_OBJECT,
                                OWNER_SECURITY_INFORMATION,
                                &pSidOwner,
                                NULL,
                                NULL,
                                NULL,
                                &pSD);

    CloseHandle(hFile);


    if (!ConvertSidToStringSid(pSidOwner, sid)) {
        *sid = NULL;
        mdebug1("The user's SID could not be extracted.");
    }

    // Check GetLastError for GetSecurityInfo error condition.
    if (dwRtnCode != ERROR_SUCCESS) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        merror("GetSecurityInfo error = %lu", dwErrorCode);
        *AcctName = '\0';
        goto end;
    }

    // Second call to LookupAccountSid to get the account name.
    bRtnBool = LookupAccountSid(
                                NULL,                   // name of local or remote computer
                                pSidOwner,              // security identifier
                                AcctName,               // account name buffer
                                (LPDWORD)&dwAcctName,   // size of account name buffer
                                DomainName,             // domain name
                                (LPDWORD)&dwDomainName, // size of domain name buffer
                                &eUse);                 // SID type

    // Check GetLastError for LookupAccountSid error condition.
    if (bRtnBool == FALSE) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();

        if (dwErrorCode == ERROR_NONE_MAPPED)
            mdebug1("Account owner not found for file '%s'", path);
        else
            merror("Error in LookupAccountSid.");

        *AcctName = '\0';
    }

end:
    if (pSD) {
        LocalFree(pSD);
    }
    return AcctName;
}

const char *get_group(__attribute__((unused)) int gid) {
    return "";
}

#endif
