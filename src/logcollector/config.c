/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"

int accept_remote;
int lc_debug_level;

/* Read the config file (the localfiles) */
int LogCollectorConfig(const char *cfgfile)
{
    int modules = 0;
    logreader_config log_config;

    modules |= CLOCALFILE;
    modules |= CSOCKET;

    log_config.config = NULL;
    log_config.socket_list = NULL;
    log_config.agent_cfg = 0;
    accept_remote = getDefine_Int("logcollector", "remote_commands", 0, 1);
    log_config.accept_remote = accept_remote;

    /* Get loop timeout */
    loop_timeout = getDefine_Int("logcollector", "loop_timeout", 1, 120);
    open_file_attempts = getDefine_Int("logcollector", "open_attempts", 2, 998);
    vcheck_files = getDefine_Int("logcollector", "vcheck_files", 0, 1024);
    maximum_lines = getDefine_Int("logcollector", "max_lines", 0, 1000000);
    sock_fail_time = getDefine_Int("logcollector", "sock_fail_time", 1, 3600);
    sample_log_length = getDefine_Int("logcollector", "sample_log_length", 1, 4096);

    if (maximum_lines > 0 && maximum_lines < 100) {
        merror("Definition 'logcollector.max_lines' must be 0 or 100..1000000.");
        return OS_INVALID;
    }

    if (ReadConfig(modules, cfgfile, &log_config, NULL) < 0) {
        return (OS_INVALID);
    }

#ifdef CLIENT
    modules |= CAGENT_CONFIG;
    log_config.agent_cfg = 1;
    ReadConfig(modules, AGENTCONFIG, &log_config, NULL);
    log_config.agent_cfg = 0;
#endif

    logff = log_config.config;
    logsk = log_config.socket_list;

    // List readed sockets
    unsigned int sk;
    for (sk=0; logsk && logsk[sk].name; sk++) {
        mdebug1("Socket '%s' (%s) added. Location: %s", logsk[sk].name, logsk[sk].mode == UDP_PROTO ? "udp" : "tcp", logsk[sk].location);
    }

    // Check sockets
    if (logff) {
        int i, j, k, r, count_localfiles = 0;
        for (i=0;logff[i].file;i++) {
            os_malloc(sizeof(logsocket), logff[i].log_target);

            for (j=0;logff[i].target[j];j++) {
                os_realloc(logff[i].log_target, (j + 2) * sizeof(logsocket), logff[i].log_target);
                memset(logff[i].log_target + j, 0, sizeof(logsocket));

                if (strcmp(logff[i].target[j], "agent") == 0) {
                    logff[i].log_target[j].log_socket = &default_agent;
                    continue;
                }
                int found = -1;
                for (k=0;logsk && logsk[k].name;k++) {
                    found = strcmp(logsk[k].name, logff[i].target[j]);
                    if (found == 0) {
                        break;
                    }
                }
                if (found != 0) {
                    merror_exit("Socket '%s' for '%s' is not defined.", logff[i].target[j], logff[i].file);
                } else {
                    logff[i].log_target[j].log_socket = &logsk[k];
                }
            }

            memset(logff[i].log_target + j, 0, sizeof(logsocket));

            // Add output formats

            if (logff[i].out_format) {
                for (j = 0; logff[i].out_format[j]; ++j) {
                    if (logff[i].out_format[j]->target) {
                        // Fill the corresponding target

                        for (k = 0; logff[i].target[k]; k++) {
                            if (strcmp(logff[i].target[k], logff[i].out_format[j]->target) == 0) {
                                logff[i].log_target[k].format = logff[i].out_format[j]->format;
                                break;
                            }
                        }

                        if (!logff[i].target[k]) {
                            mwarn("Log target '%s' wat not found for the output format of localfile '%s'.", logff[i].out_format[j]->target, logff[i].file);
                        }
                    } else {
                        // Fill the targets that don't have a format yet

                        for (k = 0; logff[i].target[k]; k++) {
                            if (!logff[i].log_target[k].format) {
                                logff[i].log_target[k].format = logff[i].out_format[j]->format;
                            }
                        }
                    }
                }
            }
        }

        /* Remove duplicate entries */

        for (i = 0;; i++) {
            if (logff[i].file == NULL) {
                break;
            }
            for (r = 0; r < i; r++) {
                if (logff[r].file && strcmp(logff[i].file, logff[r].file) == 0) {
                    mwarn("Duplicated log file given: '%s'.", logff[i].file);
                    logff[r].duplicated = 1;
                    count_localfiles--;
                    break;
                }
            }
            count_localfiles++;
        }
        mdebug1("Added %i valid 'localfile' entries.", count_localfiles);
    }

    return (1);
}

cJSON *getLocalfileConfig(void) {

    if (!max_file) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *localfiles = cJSON_CreateArray();
    int i, j;

    for (i=0;i<max_file ;i++) {
        cJSON *file = cJSON_CreateObject();

        if (logff[i].file) cJSON_AddStringToObject(file,"file",logff[i].file);
        if (logff[i].logformat) cJSON_AddStringToObject(file,"logformat",logff[i].logformat);
        if (logff[i].command) cJSON_AddStringToObject(file,"command",logff[i].command);
        if (logff[i].djb_program_name) cJSON_AddStringToObject(file,"djb_program_name",logff[i].djb_program_name);
        if (logff[i].alias) cJSON_AddStringToObject(file,"alias",logff[i].alias);
        if (logff[i].query) cJSON_AddStringToObject(file,"query",logff[i].query);
        if (*logff[i].target) {
            cJSON *target = cJSON_CreateArray();
            for (j=0;logff[i].target[j];j++) {
                cJSON_AddItemToArray(target, cJSON_CreateString(logff[i].target[j]));
            }
            cJSON_AddItemToObject(file,"target",target);
        }
        if (logff[i].out_format && *logff[i].out_format) {
            cJSON *outformat = cJSON_CreateArray();
            for (j=0;logff[i].out_format[j] && logff[i].out_format[j]->format;j++) {
                cJSON *item = cJSON_CreateObject();
                if (logff[i].out_format[j]->target)
                    cJSON_AddStringToObject(item,"target",logff[i].out_format[j]->target);
                else
                    cJSON_AddStringToObject(item,"target","all");
                cJSON_AddStringToObject(item,"format",logff[i].out_format[j]->format);
                cJSON_AddItemToArray(outformat, item);
            }
            cJSON_AddItemToObject(file,"out_format",outformat);
        }
        if (logff[i].duplicated) cJSON_AddNumberToObject(file,"duplicate",logff[i].duplicated);
        if (logff[i].labels[0].key) {
            cJSON *label = cJSON_CreateObject();
            for (j=0;logff[i].labels[j].key;j++) {
                cJSON_AddStringToObject(label,logff[i].labels[j].key,logff[i].labels[j].value);
            }
            cJSON_AddItemToObject(file,"labels",label);
        }
        if (logff[i].ign) cJSON_AddNumberToObject(file,"frequency",logff[i].ign);
        if (logff[i].future) cJSON_AddStringToObject(file,"only-future-events","yes");

        cJSON_AddItemToArray(localfiles, file);
    }

    if (cJSON_GetArraySize(localfiles) > 0) {
        cJSON_AddItemToObject(root,"localfile",localfiles);
    }

    return root;
}

cJSON *getSocketConfig(void) {

    if (!logsk) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *targets = cJSON_CreateArray();
    int i;

    for (i=0;logsk[i].name;i++) {
        cJSON *target = cJSON_CreateObject();

        cJSON_AddStringToObject(target,"name",logsk[i].name);
        cJSON_AddStringToObject(target,"location",logsk[i].location);
        if (logsk[i].mode == UDP_PROTO) {
            cJSON_AddStringToObject(target,"mode","udp");
        } else {
            cJSON_AddStringToObject(target,"mode","tcp");
        }
        if (logsk[i].prefix) cJSON_AddStringToObject(target,"prefix",logsk[i].prefix);

        cJSON_AddItemToArray(targets, target);
    }

    if (cJSON_GetArraySize(targets) > 0) {
        cJSON_AddItemToObject(root,"target",targets);
    }

    return root;
}

cJSON *getLogcollectorInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *internals = cJSON_CreateObject();
    cJSON *logcollector = cJSON_CreateObject();

    cJSON_AddNumberToObject(logcollector,"remote_commands",accept_remote);
    cJSON_AddNumberToObject(logcollector,"loop_timeout",loop_timeout);
    cJSON_AddNumberToObject(logcollector,"open_attempts",open_file_attempts);
    cJSON_AddNumberToObject(logcollector,"vcheck_files",vcheck_files);
    cJSON_AddNumberToObject(logcollector,"max_lines",maximum_lines);
    cJSON_AddNumberToObject(logcollector,"sock_fail_time",sock_fail_time);
    cJSON_AddNumberToObject(logcollector,"debug",lc_debug_level);

    cJSON_AddItemToObject(internals,"logcollector",logcollector);
    cJSON_AddItemToObject(root,"internal",internals);

    return root;
}
