/*
 * Wazuh Module for custom command execution
 * Copyright (C) 2017 Wazuh Inc.
 * October 26, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

static void * wm_command_main(wm_command_t * command);    // Module main function. It won't return
static void wm_command_destroy(wm_command_t * command);   // Destroy data
cJSON *wm_command_dump(const wm_command_t * command);

// Command module context definition

const wm_context WM_COMMAND_CONTEXT = {
    "command",
    (wm_routine)wm_command_main,
    (wm_routine)wm_command_destroy,
    (cJSON * (*)(const void *))wm_command_dump
};

// Module module main function. It won't return.

void * wm_command_main(wm_command_t * command) {
    time_t time_start;
    time_t time_sleep = 0;
    size_t extag_len;
    char * extag;
    int usec = 1000000 / wm_max_eps;

    if (!command->enabled) {
        mtwarn(WM_COMMAND_LOGTAG, "Module command:%s is disabled. Exiting.", command->tag);
        pthread_exit(0);
    }

#ifdef CLIENT
    if (!getDefine_Int("wazuh_command", "remote_commands", 0, 1) && command->agent_cfg) {
        mtwarn(WM_COMMAND_LOGTAG, "Remote commands are disabled. Ignoring '%s'.", command->tag);
        pthread_exit(0);
    }
#endif

    mtinfo(WM_COMMAND_LOGTAG, "Module command:%s started", command->tag);

    // Set extended tag

    extag_len = strlen(WM_COMMAND_CONTEXT.name) + strlen(command->tag) + 2;
    os_malloc(extag_len * sizeof(char), extag);
    snprintf(extag, extag_len, "%s_%s", WM_COMMAND_CONTEXT.name, command->tag);

    if (wm_state_io(extag, WM_IO_READ, &command->state, sizeof(command->state)) < 0) {
        memset(&command->state, 0, sizeof(command->state));
    }

    // Connect to socket

#ifndef WIN32
    if (!command->ignore_output) {
        int i;

        for (i = 0; command->queue_fd = StartMQ(DEFAULTQPATH, WRITE), command->queue_fd < 0 && i < WM_MAX_ATTEMPTS; i++) {
            sleep(WM_MAX_WAIT);
        }

        if (i == WM_MAX_ATTEMPTS) {
            mterror(WM_COMMAND_LOGTAG, "Can't connect to queue.");
            pthread_exit(NULL);
        }
    }
#endif

    // First sleeping

    if (!command->run_on_start) {
        time_start = time(NULL);

        if (command->state.next_time > time_start) {
            mtinfo(WM_COMMAND_LOGTAG, "%s: Waiting for turn to evaluate.", command->tag);
            sleep(command->state.next_time - time_start);
        }
    }

    while (1) {
        int status;
        char * output = NULL;

        mtdebug1(WM_COMMAND_LOGTAG, "Starting command '%s'.", command->tag);

        // Get time and execute
        time_start = time(NULL);

        switch (wm_exec(command->command, command->ignore_output ? NULL : &output, &status, command->timeout)) {
        case 0:
            if (status > 0) {
                mtwarn(WM_COMMAND_LOGTAG, "Command '%s' returned exit code %d.", command->tag, status);

                if (!command->ignore_output) {
                    mtdebug2(WM_COMMAND_LOGTAG, "OUTPUT: %s", output);
                }
            }

            break;

        default:
            mterror(WM_COMMAND_LOGTAG, "%s: Internal calling. Exiting...", command->tag);
            pthread_exit(NULL);
        }

        if (!command->ignore_output) {
            char * line;

            for (line = strtok(output, "\n"); line; line = strtok(NULL, "\n")){
            #ifdef WIN32
                wm_sendmsg(usec, 0, line, extag, LOCALFILE_MQ);
            #else
                wm_sendmsg(usec, command->queue_fd, line, extag, LOCALFILE_MQ);
            #endif
            }

            free(output);
        }


        mtdebug1(WM_COMMAND_LOGTAG, "Command '%s' finished.", command->tag);

        if (command->interval) {
            time_sleep = time(NULL) - time_start;

            if ((time_t)command->interval >= time_sleep) {
                time_sleep = command->interval - time_sleep;
                command->state.next_time = command->interval + time_start;
            } else {
                mtwarn(WM_COMMAND_LOGTAG, "%s: Interval overtaken.", command->tag);
                time_sleep = command->state.next_time = 0;
            }

            if (wm_state_io(extag, WM_IO_WRITE, &command->state, sizeof(command->state)) < 0)
                mterror(WM_COMMAND_LOGTAG, "%s: Couldn't save running state.", command->tag);
        }

        // If time_sleep=0, yield CPU
        sleep(time_sleep);
    }

    return NULL;
}


// Get readed data

cJSON *wm_command_dump(const wm_command_t * command) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_comm = cJSON_CreateObject();

    if (command->enabled) cJSON_AddStringToObject(wm_comm,"disabled","no"); else cJSON_AddStringToObject(wm_comm,"disabled","yes");
    if (command->run_on_start) cJSON_AddStringToObject(wm_comm,"run_on_start","yes"); else cJSON_AddStringToObject(wm_comm,"run_on_start","no");
    if (command->ignore_output) cJSON_AddStringToObject(wm_comm,"ignore_output","yes"); else cJSON_AddStringToObject(wm_comm,"ignore_output","no");
    cJSON_AddNumberToObject(wm_comm,"interval",command->interval);
    if (command->tag) cJSON_AddStringToObject(wm_comm,"tag",command->tag);
    if (command->command) cJSON_AddStringToObject(wm_comm,"command",command->command);

    cJSON_AddItemToObject(root,"command",wm_comm);

    return root;
}


// Destroy data

void wm_command_destroy(wm_command_t * command) {
    free(command->tag);
    free(command->command);
    free(command);
}
