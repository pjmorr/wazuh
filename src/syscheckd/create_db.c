/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"
#include "os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h"
#include "syscheck_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/sha256/sha256_op.h"
#include "syscheck.h"

/* Prototypes */
static int read_file(const char *dir_name, int dir_position, whodata_evt *evt, int max_depth)  __attribute__((nonnull(1)));

static int read_dir_diff(char *dir_name);

pthread_mutex_t lastcheck_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Global variables */
static int __counter = 0;

static int read_dir_diff(char *dir_name) {
    size_t dir_size;
    char f_name[PATH_MAX + 2];
    char file_name[PATH_MAX] = "\0";
    char local_dir[PATH_MAX];

    snprintf(local_dir, PATH_MAX - 1, "%s%clocal", DIFF_DIR_PATH, PATH_SEP);

    DIR *dp;
    struct dirent *entry;

    f_name[PATH_MAX + 1] = '\0';
    /* Directory should be valid */
    if ((dir_name == NULL) || ((dir_size = strlen(dir_name)) > PATH_MAX)) {
        merror(NULL_ERROR);
        return (-1);
    }

    /* Open the directory given */
    dp = opendir(dir_name);
    if (!dp) {
        if (errno == ENOTDIR || (errno == ENOENT && !strcmp(dir_name, local_dir))) {
            return 0;
        } else {
            mwarn("Accessing to '%s': [(%d) - (%s)]", dir_name, errno, strerror(errno));
            return -1;
        }
    }


    while ((entry = readdir(dp)) != NULL) {
        char *s_name;

        /* Ignore . and ..  */
        if ((strcmp(entry->d_name, ".") == 0) ||
            (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        strncpy(f_name, dir_name, PATH_MAX);
        s_name = f_name;
        s_name += dir_size;

        /* Check if the file name is already null terminated */
        if (*(s_name - 1) != PATH_SEP) {
            *s_name++ = PATH_SEP;
        }

        *s_name = '\0';
        strncpy(s_name, entry->d_name, PATH_MAX - dir_size - 2);

        if (strcmp(DIFF_LAST_FILE, s_name) == 0) {
            memset(file_name, 0, strlen(file_name));
            memmove(file_name, f_name, strlen(f_name) - strlen(s_name) - 1);
            if (OSHash_Add(syscheck.local_hash, file_name, NULL) <= 0) {
                merror("Unable to add file to db: %s", file_name);
            }
        } else {
            read_dir_diff(f_name);
        }
    }

    closedir(dp);
    return (0);
}


void remove_local_diff(){

    /* Fill hash table with the content of DIFF_DIR_PATH/local */
    char local_path[PATH_MAX] = "\0";
    const char LOCALDIR[] = {PATH_SEP, 'l', 'o', 'c', 'a', 'l', '\0'};

    strcpy(local_path, DIFF_DIR_PATH);
    strcat(local_path, LOCALDIR);

    read_dir_diff(local_path);

    unsigned int i = 0;

    /* Delete all  monitored files from hash table */
    OSHashNode *curr_node_local;
#ifdef WIN32
    OSHashNode *curr_node_monitoring;
    unsigned int j = 0;
    char full_path[PATH_MAX] = "\0";
    char *windows_path;

    for (i = 0; i <= syscheck.local_hash->rows; i++) {
        curr_node_local = syscheck.local_hash->table[i];
        for (j = 0; j <= syscheck.fp->rows; j++) {
            curr_node_monitoring = syscheck.fp->table[j];
            strcpy(full_path, local_path);
            if (curr_node_monitoring && curr_node_monitoring->key && curr_node_local && curr_node_local->key) {
                windows_path = strchr(curr_node_monitoring->key, ':');
                strcat(full_path, (windows_path + 1));
                if (strcmp(full_path, curr_node_local->key) == 0) {
                    mdebug2("Deleting '%s' from local hash table.", curr_node_local->key);
                    OSHash_Delete(syscheck.local_hash, curr_node_local->key);
                    break;
                }
            }
        }
    }
#else
    const char *monitoring_path;
    for (i = 0; i <= syscheck.local_hash->rows; i++) {
        curr_node_local = syscheck.local_hash->table[i];
        if (curr_node_local && curr_node_local->key) {
            monitoring_path = curr_node_local->key;
            monitoring_path += strlen(local_path);
            if(OSHash_Get_ex(syscheck.fp, monitoring_path)){
                mdebug2("Deleting '%s' from local hash table.", curr_node_local->key);
                OSHash_Delete(syscheck.local_hash, curr_node_local->key);
            }
            else{
                mdebug1("Couldn't get '%s' from monitoring hash table.", monitoring_path);
            }
        }
    }
#endif
    /* Delete local files that aren't monitored */
    for (i = 0; i <= syscheck.local_hash->rows; i++) {
        curr_node_local = syscheck.local_hash->table[i];
        if (curr_node_local && curr_node_local->key) {
            mdebug1("Deleting '%s'. Not monitored anymore.", curr_node_local->key);
            if (rmdir_ex(curr_node_local->key) != 0) {
                mwarn("Could not delete of filesystem '%s'", curr_node_local->key);
            }
            remove_empty_folders(curr_node_local->key);

            if (OSHash_Delete(syscheck.local_hash, curr_node_local->key) != 0) {
                mwarn("Could not delete from hash table '%s'", curr_node_local->key);
            }
        }
    }
}

/* Read and generate the integrity data of a file */
static int read_file(const char *file_name, int dir_position, whodata_evt *evt, int max_depth)
{
    int opts;
    OSMatch *restriction;
    char *buf;
    syscheck_node *s_node;
    struct stat statbuf;
    char wd_sum[OS_SIZE_6144 + 1];
#ifdef WIN32
    const char *user;
    char *sid = NULL;
#endif

    opts = syscheck.opts[dir_position];
    restriction = syscheck.filerestrict[dir_position];

    if (fim_check_ignore (file_name) == 1) {
        mdebug1("Ingnoring file '%s', continuing...", file_name);
        return (0);
    }

#ifdef WIN32
    /* Win32 does not have lstat */
    if (stat(file_name, &statbuf) < 0)
#else
    if (lstat(file_name, &statbuf) < 0)
#endif
    {
        char alert_msg[OS_SIZE_6144];

        switch (errno) {
        case ENOENT:
            mwarn("Cannot access '%s': it was removed during scan.", file_name);
            return (-1);

        case ENOTDIR:
            /*Deletion message sending*/
            alert_msg[OS_SIZE_6144 - 1] = '\0';
            snprintf(alert_msg, OS_SIZE_6144, "-1!:::::::::::%s %s", syscheck.tag[dir_position] ? syscheck.tag[dir_position] : "", file_name);
            send_syscheck_msg(alert_msg);

            // Delete from hash table
            if (s_node = OSHash_Delete_ex(syscheck.fp, file_name), s_node) {
                free(s_node->checksum);
                free(s_node);
            }

            return (0);

        default:
            merror("Error accessing '%s': %s (%d)", file_name, strerror(errno), errno);
            return (-1);
        }
    }

    if (S_ISDIR(statbuf.st_mode)) {
#ifdef WIN32
        /* Directory links are not supported */
        if (GetFileAttributes(file_name) & FILE_ATTRIBUTE_REPARSE_POINT) {
            mwarn("Links are not supported: '%s'", file_name);
            return (-1);
        }
#endif
        return (read_dir(file_name, dir_position, NULL, max_depth-1));

    }

    if (fim_check_restrict (file_name, restriction) == 1) {
        mdebug1("Ingnoring file '%s' for a restriction...", file_name);
        return (0);
    }

    /* No S_ISLNK on Windows */
#ifdef WIN32
    if (S_ISREG(statbuf.st_mode))
#else
    if (S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode))
#endif
    {
        mdebug2("REG File '%s'", file_name);
        os_md5 mf_sum;
        os_sha1 sf_sum;
        os_sha256 sf256_sum;

        /* Clean sums */
        strncpy(mf_sum, "", 1);
        strncpy(sf_sum, "", 1);
        strncpy(sf256_sum, "", 1);

        /* Generate checksums */
        if ((opts & CHECK_MD5SUM) || (opts & CHECK_SHA1SUM) || (opts & CHECK_SHA256SUM)) {
            /* If it is a link, check if dest is valid */
#ifndef WIN32
            if (S_ISLNK(statbuf.st_mode)) {
                struct stat statbuf_lnk;
                if (stat(file_name, &statbuf_lnk) == 0) {
                    if (S_ISREG(statbuf_lnk.st_mode)) {
                        if (OS_MD5_SHA1_SHA256_File(file_name, syscheck.prefilter_cmd, mf_sum,sf_sum, sf256_sum, OS_BINARY) < 0) {
                            strncpy(mf_sum, "n/a", 4);
                            strncpy(sf_sum, "n/a", 4);
                            strncpy(sf256_sum, "n/a", 4);
                        }
                    }
                }
            } else if (OS_MD5_SHA1_SHA256_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, sf256_sum, OS_BINARY) < 0)
#else
            if (OS_MD5_SHA1_SHA256_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, sf256_sum, OS_BINARY) < 0)
#endif
            {
                strncpy(mf_sum, "n/a", 4);
                strncpy(sf_sum, "n/a", 4);
                strncpy(sf256_sum, "n/a", 4);
            }
        }

        if (s_node = (syscheck_node *) OSHash_Get_ex(syscheck.fp, file_name), !s_node) {
            char alert_msg[OS_MAXSTR + 1];    /* to accommodate a long */
            alert_msg[OS_MAXSTR] = '\0';
            char * alertdump = NULL;

            if (opts & CHECK_SEECHANGES) {
                alertdump = seechanges_addfile(file_name);
            }
#ifdef WIN32
            user = get_user(file_name, statbuf.st_uid, &sid);
            snprintf(alert_msg, OS_MAXSTR, "%c%c%c%c%c%c%c%c%c%c%ld:%d:%s::%s:%s:%s:%s:%ld:%ld:%s",
                    opts & CHECK_SIZE ? '+' : '-',
                    opts & CHECK_PERM ? '+' : '-',
                    opts & CHECK_OWNER ? '+' : '-',
                    opts & CHECK_GROUP ? '+' : '-',
                    opts & CHECK_MD5SUM ? '+' : '-',
                    opts & CHECK_SHA1SUM ? '+' : '-',
                    opts & CHECK_MTIME ? '+' : '-',
                    opts & CHECK_INODE ? '+' : '-',
                    opts & CHECK_SHA256SUM ? '+' : '-',
                    opts & CHECK_SEECHANGES ? '+' : '-',
                    opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                    opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                    (opts & CHECK_OWNER) && sid ? sid : "",
                    opts & CHECK_MD5SUM ? mf_sum : "",
                    opts & CHECK_SHA1SUM ? sf_sum : "",
                    opts & CHECK_OWNER ? user : "",
                    opts & CHECK_GROUP ? get_group(statbuf.st_gid) : "",
                    opts & CHECK_MTIME ? (long)statbuf.st_mtime : 0,
                    opts & CHECK_INODE ? (long)statbuf.st_ino : 0,
                    opts & CHECK_SHA256SUM ? sf256_sum : "");

                if (sid) {
                     LocalFree(sid);
                 }
#else
            snprintf(alert_msg, OS_MAXSTR, "%c%c%c%c%c%c%c%c%c%c%ld:%d:%d:%d:%s:%s:%s:%s:%ld:%ld:%s",
                    opts & CHECK_SIZE ? '+' : '-',
                    opts & CHECK_PERM ? '+' : '-',
                    opts & CHECK_OWNER ? '+' : '-',
                    opts & CHECK_GROUP ? '+' : '-',
                    opts & CHECK_MD5SUM ? '+' : '-',
                    opts & CHECK_SHA1SUM ? '+' : '-',
                    opts & CHECK_MTIME ? '+' : '-',
                    opts & CHECK_INODE ? '+' : '-',
                    opts & CHECK_SHA256SUM ? '+' : '-',
                    opts & CHECK_SEECHANGES ? '+' : '-',
                    opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                    opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                    opts & CHECK_OWNER ? (int)statbuf.st_uid : 0,
                    opts & CHECK_GROUP ? (int)statbuf.st_gid : 0,
                    opts & CHECK_MD5SUM ? mf_sum : "",
                    opts & CHECK_SHA1SUM ? sf_sum : "",
                    opts & CHECK_OWNER ? get_user(file_name, statbuf.st_uid, NULL) : "",
                    opts & CHECK_GROUP ? get_group(statbuf.st_gid) : "",
                    opts & CHECK_MTIME ? (long)statbuf.st_mtime : 0,
                    opts & CHECK_INODE ? (long)statbuf.st_ino : 0,
                    opts & CHECK_SHA256SUM ? sf256_sum : "");
#endif

            os_calloc(1, sizeof(syscheck_node), s_node);
            s_node->checksum = strdup(alert_msg);
            s_node->dir_position = dir_position;

            if (OSHash_Add_ex(syscheck.fp, file_name, s_node) <= 0) {
                free(s_node->checksum);
                free(s_node);
                merror("Unable to add file to db: %s", file_name);
            }

            /* Send the new checksum to the analysis server */
            alert_msg[OS_MAXSTR] = '\0';

            /* Extract the whodata sum here to not include it in the hash table */
            if (extract_whodata_sum(evt, wd_sum, OS_SIZE_6144)) {
                merror("The whodata sum for '%s' file could not be included in the alert as it is too large.", file_name);
            }

#ifdef WIN32
            user = get_user(file_name, statbuf.st_uid, &sid);
            snprintf(alert_msg, OS_MAXSTR, "%ld:%d:%s::%s:%s:%s:%s:%ld:%ld:%s!%s:%s %s%s%s",
                opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                (opts & CHECK_OWNER) && sid ? sid : "",
                opts & CHECK_MD5SUM ? mf_sum : "",
                opts & CHECK_SHA1SUM ? sf_sum : "",
                opts & CHECK_OWNER ? user : "",
                opts & CHECK_GROUP ? get_group(statbuf.st_gid) : "",
                opts & CHECK_MTIME ? (long)statbuf.st_mtime : 0,
                opts & CHECK_INODE ? (long)statbuf.st_ino : 0,
                opts & CHECK_SHA256SUM ? sf256_sum : "",
                wd_sum,
                syscheck.tag[dir_position] ? syscheck.tag[dir_position] : "",
                file_name,
                alertdump ? "\n" : "",
                alertdump ? alertdump : "");
            if (sid) {
                LocalFree(sid);
            }
#else
            snprintf(alert_msg, OS_MAXSTR, "%ld:%d:%d:%d:%s:%s:%s:%s:%ld:%ld:%s!%s:%s %s%s%s",
                opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                opts & CHECK_OWNER ? (int)statbuf.st_uid : 0,
                opts & CHECK_GROUP ? (int)statbuf.st_gid : 0,
                opts & CHECK_MD5SUM ? mf_sum : "",
                opts & CHECK_SHA1SUM ? sf_sum : "",
                opts & CHECK_OWNER ? get_user(file_name, statbuf.st_uid, NULL) : "",
                opts & CHECK_GROUP ? get_group(statbuf.st_gid) : "",
                opts & CHECK_MTIME ? (long)statbuf.st_mtime : 0,
                opts & CHECK_INODE ? (long)statbuf.st_ino : 0,
                opts & CHECK_SHA256SUM ? sf256_sum : "",
                wd_sum,
                syscheck.tag[dir_position] ? syscheck.tag[dir_position] : "",
                file_name,
                alertdump ? "\n" : "",
                alertdump ? alertdump : "");
#endif
            if(max_depth <= syscheck.max_depth){
                send_syscheck_msg(alert_msg);
            }
            free(alertdump);
        } else {
            char alert_msg[OS_MAXSTR + 1];
            char c_sum[OS_MAXSTR + 1];

            buf = s_node->checksum;
            c_sum[0] = '\0';
            c_sum[OS_MAXSTR] = '\0';
            alert_msg[0] = '\0';
            alert_msg[OS_MAXSTR] = '\0';

            /* If it returns < 0, we have already alerted */
            if (c_read_file(file_name, buf, c_sum, NULL) < 0) {
                return (0);
            }

            w_mutex_lock(&lastcheck_mutex);
            OSHash_Delete(syscheck.last_check, file_name);
            w_mutex_unlock(&lastcheck_mutex);

            if (strcmp(c_sum, buf + SK_DB_NATTR)) {
                // Extract the whodata sum here to not include it in the hash table
                if (extract_whodata_sum(evt, wd_sum, OS_SIZE_6144)) {
                    merror("The whodata sum for '%s' file could not be included in the alert as it is too large.", file_name);
                }
                // Update database
                snprintf(alert_msg, sizeof(alert_msg), "%.*s%.*s", SK_DB_NATTR, buf, (int)strcspn(c_sum, " "), c_sum);
                s_node->checksum = strdup(alert_msg);

                /* Send the new checksum to the analysis server */
                alert_msg[OS_MAXSTR] = '\0';
                char *fullalert = NULL;
                if (buf[9] == '+') {
                    fullalert = seechanges_addfile(file_name);
                    if (fullalert) {
                        snprintf(alert_msg, OS_MAXSTR, "%s!%s:%s %s\n%s",
                                c_sum, wd_sum, syscheck.tag[dir_position] ? syscheck.tag[dir_position] : "", file_name, fullalert);
                        free(fullalert);
                        fullalert = NULL;
                    } else {
                        snprintf(alert_msg, OS_MAXSTR, "%s!%s:%s %s",
                                c_sum, wd_sum, syscheck.tag[dir_position] ? syscheck.tag[dir_position] : "", file_name);
                    }
                } else {
                    snprintf(alert_msg, OS_MAXSTR, "%s!%s:%s %s",
                            c_sum, wd_sum, syscheck.tag[dir_position] ? syscheck.tag[dir_position] : "", file_name);
                }
                free(buf);
                send_syscheck_msg(alert_msg);
            }
        }

        /* Sleep here too */
        if (__counter >= (syscheck.sleep_after)) {
            sleep(syscheck.tsleep);
            __counter = 0;
        }
        __counter++;
    } else {
        mdebug2("IRREG File: '%s'", file_name);
    }

    return (0);
}

int read_dir(const char *dir_name, int dir_position, whodata_evt *evt, int max_depth)
{
    if(max_depth < 0){
        mdebug2("Max level of recursion reached. File '%s' out of bounds.", dir_name);
        return 0;
    }

    int opts;
    size_t dir_size;
    char f_name[PATH_MAX + 2];
    short is_nfs;

    DIR *dp;
    struct dirent *entry;

    f_name[PATH_MAX + 1] = '\0';

    opts = syscheck.opts[dir_position];

    /* Directory should be valid */
    if ((dir_name == NULL) || ((dir_size = strlen(dir_name)) > PATH_MAX)) {
        merror(NULL_ERROR);
        return (-1);
    }

    /* Should we check for NFS? */
    if (syscheck.skip_nfs)
    {
        is_nfs = IsNFS(dir_name);
        if (is_nfs != 0)
        {
            // Error will be -1, and 1 means skipped
            return (is_nfs);
        }
    }

    /* Open the directory given */
    dp = opendir(dir_name);
    if (!dp) {
        if (errno == ENOTDIR) {
            if (read_file(dir_name, dir_position, evt, max_depth) == 0) {
                return (0);
            }
        }

#ifdef WIN32
        int di = 0;
        char *(defaultfilesn[]) = {
            "C:\\autoexec.bat",
            "C:\\config.sys",
            "C:\\WINDOWS/System32/eventcreate.exe",
            "C:\\WINDOWS/System32/eventtriggers.exe",
            "C:\\WINDOWS/System32/tlntsvr.exe",
            "C:\\WINDOWS/System32/Tasks",
            NULL
        };
        while (defaultfilesn[di] != NULL) {
            if (strcmp(defaultfilesn[di], dir_name) == 0) {
                break;
            }
            di++;
        }
#ifdef WIN_WHODATA
        if (defaultfilesn[di] == NULL && !(evt && evt->ignore_not_exist)) {
#else
        if (defaultfilesn[di] == NULL) {
#endif
            mwarn("Cannot open '%s': %s ", dir_name, strerror(errno));
        } else {
            return 0;
        }
#else
        mwarn("Cannot open '%s': %s ", dir_name, strerror(errno));
#endif /* WIN32 */
        return (-1);
    }

    /* Check for real time flag */
    if (opts & CHECK_REALTIME || opts & CHECK_WHODATA) {
#ifdef INOTIFY_ENABLED
        realtime_adddir(dir_name, opts & CHECK_WHODATA);
#else
#ifndef WIN32
        mwarn("realtime monitoring request on unsupported system for '%s'", dir_name);
#endif
#endif
    }

    while ((entry = readdir(dp)) != NULL) {
        char *s_name;

        /* Ignore . and ..  */
        if ((strcmp(entry->d_name, ".") == 0) ||
                (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        strncpy(f_name, dir_name, PATH_MAX);
        s_name =  f_name;
        s_name += dir_size;

        /* Check if the file name is already null terminated */
#ifdef WIN32
        if (*(s_name - 1) != '\\') {
            *s_name++ = '\\';
        }
#else
        if (*(s_name - 1) != '/') {
            *s_name++ = '/';
        }
#endif

        *s_name = '\0';
        strncpy(s_name, entry->d_name, PATH_MAX - dir_size - 2);

        /* Check integrity of the file */
        read_file(f_name, dir_position, NULL, max_depth);
    }

    closedir(dp);
    return (0);
}

int run_dbcheck()
{
    unsigned int i = 0;
    char alert_msg[OS_SIZE_6144];
    OSHash *last_backup;
    OSHashNode *curr_node;
    syscheck_node *data;
    int pos;

    __counter = 0;
    while (syscheck.dir[i] != NULL) {
#ifdef WIN_WHODATA
        if (syscheck.wdata.dirs_status[i].status & WD_CHECK_REALTIME) {
            // At this point the directories in whodata mode that have been deconfigured are added to realtime
            syscheck.wdata.dirs_status[i].status &= ~WD_CHECK_REALTIME;
            if (realtime_adddir(syscheck.dir[i], 0) != 1) {
                merror("The '%s' directory could not be added to realtime mode.", syscheck.dir[i]);
            } else {
                mdebug1("The '%s' directory starts to be monitored in real-time mode", syscheck.dir[i]);
            }
        }
#endif
        read_dir(syscheck.dir[i], i, NULL, syscheck.max_depth);
        i++;
    }

    if (syscheck.dir[0]) {
        // Check for deleted files
        w_mutex_lock(&lastcheck_mutex);
        last_backup = syscheck.last_check;

        // Prepare last_check for next scan
        syscheck.last_check = OSHash_Duplicate_ex(syscheck.fp);
        w_mutex_unlock(&lastcheck_mutex);

        // Send messages for deleted files
        for (i = 0; i <= last_backup->rows; i++) {
            curr_node = last_backup->table[i];
            if(curr_node && curr_node->key) {

                pos = find_dir_pos(curr_node->key, 1, 0, 0);
                mdebug2("Sending delete msg for file: %s", curr_node->key);
                snprintf(alert_msg, OS_SIZE_6144 - 1, "-1!:::::::::::%s %s", syscheck.tag[pos] ? syscheck.tag[pos] : "", curr_node->key);
                send_syscheck_msg(alert_msg);
                OSHash_Delete_ex(syscheck.last_check, curr_node->key);
                if (data = OSHash_Delete_ex(syscheck.fp, curr_node->key), data) {
                    free(data->checksum);
                    free(data);
                }
            }
        }

        OSHash_Free(last_backup);

        // Check and delete backup local/diff
        if (syscheck.remove_old_diff) {
            remove_local_diff();
        }
    }


    return (0);
}

int create_db()
{
    int i = 0;
#ifdef WIN_WHODATA
    int enable_who_scan = 0;
    HANDLE t_hdle;
    long unsigned int t_id;
#endif

    if (!syscheck.fp) {
        merror_exit("Unable to create syscheck database. Exiting.");
    }

    if (!OSHash_setSize_ex(syscheck.fp, 2048)) {
        merror(LIST_ERROR);
        return (0);
    }
    if (!OSHash_setSize(syscheck.local_hash, 2048)) {
        merror(LIST_ERROR);
        return (0);
    }

    if ((syscheck.dir == NULL) || (syscheck.dir[0] == NULL)) {
        merror("No directories to check.");
        return (-1);
    }

    minfo("Starting syscheck database (pre-scan).");

    /* Read all available directories */
    __counter = 0;
    do {
        if (read_dir(syscheck.dir[i], i, NULL, syscheck.max_depth) == 0) {
            mdebug2("Directory loaded from syscheck db: %s", syscheck.dir[i]);
        }
#ifdef WIN32
        if (syscheck.opts[i] & CHECK_WHODATA) {
#ifdef WIN_WHODATA
            realtime_adddir(syscheck.dir[i], i + 1);
            if (!enable_who_scan) {
                enable_who_scan = 1;
            }
#endif
        } else if (syscheck.opts[i] & CHECK_REALTIME) {
            realtime_adddir(syscheck.dir[i], 0);
        }
#else
#ifndef INOTIFY_ENABLED
        // Realtime mode on Linux requires inotify
        if (syscheck.opts[i] & CHECK_REALTIME) {
            mwarn("realtime monitoring request on unsupported system for '%s'", syscheck.dir[i]);
        }
#endif
#endif
        i++;
    } while (syscheck.dir[i] != NULL);

    if(syscheck.remove_old_diff) {
        remove_local_diff();
    }

    w_mutex_lock(&lastcheck_mutex);
    OSHash_Free(syscheck.last_check);
    /* Duplicate hash table to check for deleted files */
    syscheck.last_check = OSHash_Duplicate(syscheck.fp);
    w_mutex_unlock(&lastcheck_mutex);

#if defined (INOTIFY_ENABLED) || defined (WIN32)
    if (syscheck.realtime && (syscheck.realtime->fd >= 0)) {
        minfo("Real time file monitoring engine started.");
    }
#endif
#ifdef WIN_WHODATA
    if (enable_who_scan && !run_whodata_scan()) {
        minfo("Whodata auditing engine started.");
        if (t_hdle = CreateThread(NULL, 0, state_checker, NULL, 0, &t_id), !t_hdle) {
            merror("Could not create the Whodata check thread.");
        }
    }
#endif
    minfo("Finished creating syscheck database (pre-scan completed).");
    return (0);
}

int extract_whodata_sum(whodata_evt *evt, char *wd_sum, int size) {
    int retval = 0;
    if (!evt) {
        if (snprintf(wd_sum, size, "::::::::::") >= size) {
            retval = 1;
        }
    } else {
        char *process_esc = NULL;
        char *name_esc = evt->user_name;
        char *esc_it = NULL;

        // Escape process
        esc_it = wstr_replace(evt->process_name, ":", "\\:");
        process_esc = wstr_replace(esc_it, " ", "\\ ");

#ifdef WIN32
        // Only Windows agents can have spaces in their names
        name_esc = wstr_replace(evt->user_name, " ", "\\ ");
#endif
        if (snprintf(wd_sum, size, "%s:%s:%s:%s:%s:%s:%s:%s:%s:%i:%lli",
                evt->user_id,
                name_esc,
                (evt->group_id)?evt->group_id:"",
                (evt->group_name)?evt->group_name:"",
                process_esc,
                (evt->audit_uid)?evt->audit_uid:"",
                (evt->audit_name)?evt->audit_name:"",
                (evt->effective_uid)?evt->effective_uid:"",
                (evt->effective_name)?evt->effective_name:"",
                evt->ppid,
                (long long unsigned int) evt->process_id
            ) >= size) {
            retval = 1;
            snprintf(wd_sum, size, "::::::::::");
        }

#ifdef WIN32
        free(name_esc);
#endif
        free(process_esc);
        free(esc_it);
    }
    return retval;
}

int fim_check_ignore (const char *file_name) {
    /* Check if the file should be ignored */
    if (syscheck.ignore) {
        int i = 0;
        while (syscheck.ignore[i] != NULL) {
            if (strncasecmp(syscheck.ignore[i], file_name, strlen(syscheck.ignore[i])) == 0) {
                return (1);
            }
            i++;
        }
    }

    /* Check in the regex entry */
    if (syscheck.ignore_regex) {
        int i = 0;
        while (syscheck.ignore_regex[i] != NULL) {
            if (OSMatch_Execute(file_name, strlen(file_name), syscheck.ignore_regex[i])) {
                return (1);
            }
            i++;
        }
    }

    return (0);
}

int fim_check_restrict (const char *file_name, OSMatch *restriction) {
    /* Restrict file types */
    if (restriction) {
        if (!OSMatch_Execute(file_name, strlen(file_name), restriction)) {
            return (1);
        }
    }

    return (0);
}
