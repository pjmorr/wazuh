#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import threading
import time
import shutil
import json
import os
import fcntl
import ast

from wazuh.exception import WazuhException
from wazuh import common
from wazuh.cluster.cluster import get_cluster_items, _update_file, decompress_files, get_files_status, compress_files, compare_files, get_agents_status, clean_up, read_config
from wazuh.cluster.communication import ProcessFiles, Server, ServerHandler, Handler, InternalSocketHandler, ClusterThread
from wazuh.utils import mkdir_with_mode



#
# Master Handler
# There is a MasterManagerHandler for each connected client
#
class MasterManagerHandler(ServerHandler):

    def __init__(self, sock, server, map, addr=None):
        ServerHandler.__init__(self, sock, server, map, addr)
        self.manager = server

    # Overridden methods
    def process_request(self, command, data):
        logging.debug("[Master] Request received: '{0}'.".format(command))


        if command == 'echo-c':  # Echo
            return 'ok-c ', data.decode()
        elif command == 'sync_i_c_m_p':
            result = self.manager.get_client_status(client_id=self.name, key='sync_integrity_free')
            return 'ack', str(result)
        elif command == 'sync_ai_c_mp':
            return 'ack', str(self.manager.get_client_status(client_id=self.name, key='sync_agentinfo_free'))
        elif command == 'sync_i_c_m':  # Client syncs integrity
            pci_thread = ProcessClientIntegrity(manager=self.manager, manager_handler=self, filename=data, stopper=self.stopper)
            pci_thread.start()
            # data will contain the filename
            return 'ack', self.set_worker(command, pci_thread, data)
        elif command == 'sync_ai_c_m':
            mcf_thread = ProcessClientFiles(manager_handler=self, filename=data, stopper=self.stopper)
            mcf_thread.start()
            # data will contain the filename
            return 'ack', self.set_worker(command, mcf_thread, data)
        elif command == 'get_nodes':  # Get nodes
            response = {name:data['info'] for name,data in self.server.get_connected_clients().iteritems()}
            cluster_config = read_config()
            response.update({cluster_config['node_name']:{"name": cluster_config['node_name'], "ip": cluster_config['nodes'][0],  "type": "master"}})
            serialized_response = ['ok', json.dumps(response)]
            return serialized_response
        else:  # Non-master requests
            return ServerHandler.process_request(self, command, data)

    @staticmethod
    def process_response(response):
        # FixMe: Move this line to communications
        answer, payload = Handler.split_data(response)

        logging.debug("[Master] Response received: '{0}'.".format(answer))

        response_data = None

        if answer == 'ok-m':  # test
            response_data = '[response_only_for_master] Client answered: {}.'.format(payload)
        else:
            response_data = ServerHandler.process_response(response)

        return response_data

    # Private methods
    def _update_client_files_in_master(self, json_file, files_to_update_json, zip_dir_path):
        cluster_items = get_cluster_items()

        try:

            for file_name, data in json_file.items():
                # Full path
                file_path = common.ossec_path + file_name
                zip_path  = "{}/{}".format(zip_dir_path, file_name.replace('/','_'))

                # Cluster items information: write mode and umask
                cluster_item_key = data['cluster_item_key']
                w_mode = cluster_items[cluster_item_key]['write_mode']
                umask = int(cluster_items[cluster_item_key]['umask'], base=0)

                # File content and time
                with open(zip_path, 'rb') as f:
                    file_data = f.read()
                file_time = files_to_update_json[file_name]['mod_time']

                lock_file_path = "{}.lock".format(file_path)
                lock_file = open(lock_file_path, 'a+')
                try:
                    fcntl.lockf(lock_file, fcntl.LOCK_EX)
                    _update_file(fullpath=file_path, new_content=file_data,
                                 umask_int=umask, mtime=file_time, w_mode=w_mode,
                                 whoami='master')
                except:
                    fcntl.lockf(lock_file, fcntl.LOCK_UN)
                    lock_file.close()
                    os.remove(lock_file_path)
                    raise

                fcntl.lockf(lock_file, fcntl.LOCK_UN)
                lock_file.close()
                os.remove(lock_file_path)

        except Exception as e:
            logging.error("Error updating client files: {}".format(str(e)))
            raise e

    # New methods
    def process_files_from_client(self, client_name, data_received, tag=None):
        sync_result = False

        if not tag:
            tag = "[Master] [Sync process m->c]"

        logging.info("{0} [{1}]: Start.".format(tag, client_name))


        # Extract received data
        logging.info("{0} [{1}] [STEP 1]: Analyzing received files.".format(tag, client_name))

        try:
            json_file, zip_dir_path = decompress_files(data_received)
        except Exception as e:
            logging.error("{}: Error decompressing data from client {}: {}".format(tag, client_name, str(e)))
            raise e

        if json_file:
            client_files_json = json_file['client_files']
        else:
            raise Exception("cluster_control.json not included in received zip file")

        logging.debug("{0} Received {1} client files to update".format(tag, len(client_files_json)))



        logging.info("{0} [{1}] [STEP 2]: Updating manager files.".format(tag, client_name))

        # Update files
        self._update_client_files_in_master(client_files_json, client_files_json, zip_dir_path)

        # Remove tmp directory created when zip file was received
        shutil.rmtree(zip_dir_path)

        sync_result = True

        # Send KO files
        return sync_result


    def process_integrity_from_client(self, client_name, data_received, tag=None):
        ko_files = False
        data_for_client = None

        if not tag:
            tag = "[Master] [Sync process m->c]"

        logging.info("{0} [{1}]: Start.".format(tag, client_name))

        try:
            json_file, zip_dir_path = decompress_files(data_received)
        except Exception as e:
            logging.error("{}: Error decompressing data from client {}: {}".format(tag, client_name, str(e)))
            raise e

        if json_file:
            master_files_from_client = json_file['master_files']
        else:
            raise Exception("cluster_control.json not included in received zip file")

        # Extract recevied data
        logging.info("{0} [{1}] [STEP 1]: Analyzing received files.".format(tag, client_name))

        logging.debug("{0} Received {1} master files to check".format(tag, len(master_files_from_client)))

        # Get master files
        master_files = self.server.get_integrity_control()

        # Compare
        client_files_ko = compare_files(master_files, master_files_from_client)

        # Remove tmp directory created when zip file was received
        shutil.rmtree(zip_dir_path)

        # Step 3: KO files
        if not client_files_ko['shared'] and not client_files_ko['missing'] and not client_files_ko['extra']:
            logging.info("{0} [{1}] [STEP 2]: There are no KO files for client.".format(tag, client_name))

            ko_files = False
            data_for_client = None

        else:
            # Compress data: master files (only KO shared and missing)
            logging.info("{0} [{1}] [STEP 2]: Compressing KO files for client.".format(tag, client_name))

            master_files_paths = [item for item in client_files_ko['shared']]
            master_files_paths.extend([item for item in client_files_ko['missing']])

            compressed_data = compress_files('master', client_name, master_files_paths, client_files_ko)

            logging.info("{0} [{1}] [STEP 2]: Sending KO files to client.".format(tag, client_name))

            ko_files = True
            data_for_client = compressed_data

        return ko_files, data_for_client


#
# Threads (workers) created by MasterManagerHandler
#


class ProcessClient(ProcessFiles):

    def __init__(self, manager_handler, filename, stopper):
        ProcessFiles.__init__(self, manager_handler, filename,
                              manager_handler.get_client(),
                              stopper)

    def check_connection(self):
        return True


    def lock_status(self, status):
        # status_type is used to indicate whether a lock is free or not.
        # if the lock is True, the status should be False because it is not free
        self.manager_handler.manager.set_client_status(self.name, self.status_type, not status)


    def process_file(self):
        return self.function(self.name, self.filename, self.thread_tag)


class ProcessClientIntegrity(ProcessClient):

    def __init__(self, manager, manager_handler, filename, stopper):
        ProcessClient.__init__(self, manager_handler, filename, stopper)
        self.manager = manager
        self.thread_tag = "[Master] [ProcessIntegrityThread] [Sync process m->c]"
        self.status_type = "sync_integrity_free"
        self.function = self.manager_handler.process_integrity_from_client

    # Overridden methods
    def process_file(self):
        sync_result = False

        ko_files, data_for_client = self.function(self.name, self.filename, self.thread_tag)

        if ko_files:
            response = self.manager.send_file(self.name, 'sync_m_c', data_for_client, True)
        else:
            response = self.manager.send_request(self.name, 'sync_m_c_ok')

        processed_response = self.manager_handler.process_response(response)

        if processed_response:
            sync_result = True
            logging.info("{0} [{1}] [STEP 2]: Client received the sync properly".format(self.thread_tag, self.name))
        else:
            logging.error("{0} [{1}] [STEP 2]: Client reported an error receiving the sync.".format(self.thread_tag, self.name))

        return sync_result


    def unlock_clean_and_stop(self, reason, clean=True, send_err_request=True):

        # Send Err
        if send_err_request:
            response = self.manager.send_request(self.name, 'sync_m_c_err')
            processed_response = self.manager_handler.process_response(response)

        # Unlock, clean and stop
        ProcessClient.unlock_clean_and_stop(self, reason, clean)


class ProcessClientFiles(ProcessClient):

   def __init__(self, manager_handler, filename, stopper):
        ProcessClient.__init__(self, manager_handler, filename, stopper)
        self.thread_tag = "[Master] [ProcessClientFilesThread] [Sync process m->c]"
        self.status_type = "sync_agentinfo_free"
        self.function = self.manager_handler.process_files_from_client


#
# Master
#
class MasterManager(Server):
    Integrity_T = "Integrity_Thread"

    def __init__(self, cluster_config):
        Server.__init__(self, cluster_config['bind_addr'], cluster_config['port'], MasterManagerHandler)

        logging.info("[Master] Listening.")

        self.config = cluster_config
        self.handler = MasterManagerHandler
        self._integrity_control = {}
        self._integrity_control_lock = threading.Lock()

        # Threads
        self.stopper = threading.Event()  # Event to stop threads
        self.threads = {}
        self._initiate_master_threads()

    # Overridden methods
    def add_client(self, data, ip, handler):
        id = Server.add_client(self, data, ip, handler)
        # create directory in /queue/cluster to store all node's file there
        node_path = "{}/queue/cluster/{}".format(common.ossec_path, id)
        if not os.path.exists(node_path):
            mkdir_with_mode(node_path)
        return id


    def remove_client(self, id):
        Server.remove_client(self, id)
        node_path = "{}/queue/cluster/{}".format(common.ossec_path, id)
        if id not in self.get_connected_clients() and os.path.exists(node_path):
            shutil.rmtree(node_path)


    # Private methods
    def _initiate_master_threads(self):
        logging.debug("[Master] Creating threads.")
        self.threads[MasterManager.Integrity_T] = FileStatusUpdateThread(master=self, interval=30, stopper=self.stopper)
        self.threads[MasterManager.Integrity_T].start()

    # New methods
    def set_client_status(self, client_id, key, status):
        result = False
        with self._clients_lock:
            if client_id in self._clients:
                self._clients[client_id]['status'][key] = status
                result = True

        return result


    def get_client_status(self, client_id, key):
        result = False

        with self._clients_lock:
            if client_id in self._clients:
                result = self._clients[client_id]['status'][key]

        return result


    def req_file_status_to_clients(self):
        responses = list(self.send_request_broadcast(command = 'file_status'))
        nodes_file = {node:json.loads(data.split(' ',1)[1]) for node,data in responses}
        return 'ok', json.dumps(nodes_file)


    def get_integrity_control(self):
        with self._integrity_control_lock:
            return self._integrity_control


    def set_integrity_control(self, new_integrity_control):
        with self._integrity_control_lock:
            self._integrity_control = new_integrity_control


    def get_healtcheck(self):
        clients_info = {name:{"info":data['info'], "status":data['status']} for name,data in self.get_connected_clients().iteritems()}

        cluster_config = read_config()
        clients_info.update({cluster_config['node_name']:{"info":{"name": cluster_config['node_name'], "ip": cluster_config['nodes'][0],  "type": "master"}}})

        healtcheck = {"n_connected_nodes":len(clients_info), "nodes_info": clients_info}
        return healtcheck



    def exit(self):
        logging.info("[Master] Cleaning...")

        # Cleaning master threads
        logging.debug("[Master] Cleaning main threads")
        self.stopper.set()

        for thread in self.threads:
            logging.debug("[Master] Cleaning main threads: '{0}'.".format(thread))
            self.threads[thread].join(timeout=5)
            if self.threads[thread].isAlive():
                logging.warning("[Master] Cleaning main threads. Timeout for: '{0}'.".format(thread))
            else:
                logging.debug("[Master] Cleaning main threads. Terminated: '{0}'.".format(thread))

        # Cleaning handler threads
        logging.debug("[Master] Cleaning threads of clients.")
        clients = self.get_connected_clients().keys()
        for client in clients:
            self.remove_client(id=client)

        logging.debug("[Master] Cleaning generated temporary files.")
        clean_up()

        logging.info("[Master] Cleaning end.")


#
# Master threads
#
class FileStatusUpdateThread(ClusterThread):
    def __init__(self, master, interval, stopper):
        ClusterThread.__init__(self, stopper)
        self.master = master
        self.interval = interval


    def run(self):
        while not self.stopper.is_set() and self.running:
            logging.debug("[Master] Recalculating integrity control file.")
            tmp_integrity_control = get_files_status('master')
            self.master.set_integrity_control(tmp_integrity_control)
            #time.sleep(self.interval)
            self.sleep(self.interval)


#
# Internal socket
#
class MasterInternalSocketHandler(InternalSocketHandler):
    def __init__(self, sock, manager, map):
        InternalSocketHandler.__init__(self, sock=sock, manager=manager, map=map)

    def process_request(self, command, data):
        logging.debug("[Transport-I] Forwarding request to master of cluster '{0}' - '{1}'".format(command, data))
        serialized_response = ""

        if command == 'get_files':
            split_data = data.split('%--%', 2)
            file_list = ast.literal_eval(split_data[0]) if split_data[0] else None
            node_list = ast.literal_eval(split_data[1]) if split_data[1] else None
            get_my_files = False

            response = {}

            if node_list and len(node_list) > 0: #Selected nodes
                for node in node_list:
                    if node == read_config()['node_name']:
                        get_my_files = True
                        continue
                    node_file = self.manager.send_request(client_name=node, command='file_status', data='')

                    if node_file.split(' ', 1)[0] == 'err': # Error response
                        response.update({node:node_file.split(' ', 1)[1]})
                    else:
                        response.update({node:json.loads(node_file.split(' ',1)[1])})
            else: # Broadcast
                get_my_files = True

                node_file = list(self.manager.send_request_broadcast(command = 'file_status'))

                for node,data in node_file:
                    try:
                        response.update({node:json.loads(data.split(' ',1)[1])})
                    except: # Error response
                        response.update({node:data.split(' ',1)[1]})

            if get_my_files:
                my_files = get_files_status('master', get_md5=True)
                my_files.update(get_files_status('client', get_md5=True))
                response.update({read_config()['node_name']:my_files})

            # Filter files
            if node_list and len(response):
                response = {node: response.get(node) for node in node_list}

            serialized_response = ['ok',  json.dumps(response)]
            return serialized_response

        elif command == 'get_nodes':
            split_data = data.split(' ', 1)
            node_list = ast.literal_eval(split_data[0]) if split_data[0] else None

            response = {name:data['info'] for name,data in self.manager.get_connected_clients().iteritems()}
            cluster_config = read_config()
            response.update({cluster_config['node_name']:{"name": cluster_config['node_name'], "ip": cluster_config['nodes'][0],  "type": "master"}})

            if node_list:
                response = {node:info for node, info in response.iteritems() if node in node_list}

            serialized_response = ['ok', json.dumps(response)]
            return serialized_response

        elif command == 'get_agents':
            filter_status = data if data != 'None' else None
            response = get_agents_status(filter_status)
            serialized_response = ['ok',  json.dumps(response)]
            return serialized_response

        elif command == 'get_health':
            response = self.manager.get_healtcheck()

            serialized_response = ['ok',  json.dumps(response)]
            return serialized_response

        elif command == 'sync':
            command = "req_sync_m_c"
            split_data = data.split(' ', 1)
            node_list = ast.literal_eval(split_data[0]) if split_data[0] else None

            if node_list:
                for node in node_list:
                    response = {node:self.manager.send_request(client_name=node, command=command, data="")}
                serialized_response = ['ok', json.dumps(response)]
            else:
                response = list(self.manager.send_request_broadcast(command=command, data=data))
                serialized_response = ['ok', json.dumps({node:data for node,data in response})]
            return serialized_response

        else:
            split_data = data.split(' ', 1)
            host = split_data[0]
            data = split_data[1] if len(split_data) > 1 else None

            if host == 'all':
                response = list(self.manager.send_request_broadcast(command=command, data=data))
                serialized_response = ['ok', json.dumps({node:data for node,data in response})]
            else:
                response = self.manager.send_request(client_name=host, command=command, data=data)
                if response:
                    type_response = node_response[0]
                    response = node_response[1]

                    if type_response == "err":
                        serialized_response = {"err":response}
                    else:
                        serialized_response = response

            return serialized_response