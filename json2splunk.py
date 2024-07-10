# -*- coding: utf-8 -*-
# !/usr/bin/env python

__progname__ = "json2splunk"
__date__ = "2024-06-19"
__version__ = "0.1"
__author__ = "maxspl"

# Standard library imports
import argparse
import json
import logging as log
import operator
import os
import re
import time
import csv
import chardet
from datetime import datetime
from dateutil.parser import parse
from functools import reduce
from multiprocessing import cpu_count
from pathlib import Path

# Third-party imports
import polars as pl
import yaml
from mpire import WorkerPool
from splunk_http_event_collector import http_event_collector
from splunk_helper import SplunkHelper

LOG_FORMAT = '%(asctime)s %(levelname)s %(funcName)s: %(message)s'
LOG_VERBOSITY = {
    'DEBUG': log.DEBUG,
    'INFO': log.INFO,
    'WARNING': log.WARNING,
    'ERROR': log.ERROR,
    'CRITICAL': log.CRITICAL,
}


class FileMatcher:
    def __init__(self, config: str, test: bool):
        """
        Initialize the FileMatcher object with configuration and test mode settings.

        Args:
            config (str): Name or full path to the YAML configuration file specifying matching criteria.
            test (bool): Flag to indicate whether the class should run in test mode, affecting
                            how artifacts are recorded and how output is generated.
        """
        # Define path of patterns configuration file
        if config == 'indexer_patterns.yml':
            directory = os.path.dirname(__file__)  # Gets the directory of the current script
            relative_path = os.path.join(directory, config)
            absolute_path = os.path.abspath(relative_path) 
            patterns_config_path = absolute_path
        else:
            patterns_config_path = args.indexer_patterns
        self.config = self.load_config(patterns_config_path)
        self.test_mode = test
        self.pattern_match_count = {artifact: 0 for artifact in self.config}
        self.no_match_count = 0
        self.multi_match_count = 0
        
    @staticmethod
    def load_config(config_path: str):
        """
        Load a YAML configuration file.

        Args:
            config_path (str): The file path to the configuration file.

        Returns:
            dict: A dictionary representing the loaded configuration.
        """
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        return config

    @staticmethod
    def match_file(file_path: Path, criteria: dict):
        """
        Check if a file matches specified criteria based on name pattern and path suffix.

        Args:
            file_path (Path): The path of the file to check.
            criteria (dict): A dictionary containing 'name_rex' and 'path_suffix' keys.

        Returns:
            bool: True if the file matches the criteria, False otherwise.
        """
        name_pattern = criteria.get('name_rex')
        path_suffix = criteria.get('path_suffix')
        # Check if file name matches the name regex pattern
        if name_pattern and not re.search(name_pattern, str(file_path)):
            return False
        # Check if file path matches the path suffix
        if path_suffix and not str(file_path.parent).endswith(path_suffix.rstrip('/')):
            return False
        return True

    def _scan_directory(self, root_dir, test_mode=False):
        """
        Scan the specified directory recursively, matching files against loaded config criteria.
        If a file matches several artifacts, the first one is selected. If test mode enabled,
        dataframe is written to disk with all matching artifacts.
        Args:
            root_dir (str): The root directory to start scanning from.
            test_mode (bool): If true, additional information is recorded during the scan.

        Returns:
            list: A list of records containing details about each matched file.
        """
        records = []
        root_path = Path(root_dir)
        file_pattern_matches = {}

        for file_path in root_path.rglob('*'):
            if os.path.isfile(file_path):
                matched_artifacts = []
                matched_criterias = []
                for index, (artifact, criteria) in enumerate(self.config.items()):
                    file_name = os.path.basename(str(file_path))
                    if self.match_file(file_path, criteria):
                        matched_artifacts.append(artifact)
                        matched_criterias.append(criteria)
                    
                if matched_artifacts:
                    record = {
                        'file_path': str(file_path),
                        'file_name': file_name,
                        'artifact_name': matched_artifacts if self.test_mode and len(matched_artifacts) > 1 else matched_artifacts[0],
                        'sourcetype': matched_criterias[0].get('sourcetype', ''),
                        'timestamp_path': matched_criterias[0].get('timestamp_path', ''),
                        'timestamp_format': matched_criterias[0].get('timestamp_format', ''),
                        'host_path': None
                    }
                    
                    # Determine host from the first matched pattern
                    host_path = matched_criterias[0].get('host_path', '')
                    host_rex = matched_criterias[0].get('host_rex', '')
                    record['host'] = 'Unknown'
                    if host_rex:  # Try to extract host from file name if host_rex defined
                        criteria = self.config[matched_artifacts[0]]
                        host_match = re.search(host_rex, str(file_path))
                        host = host_match.group(1) if host_match else 'Unknown'
                        record['host'] = host
                    elif host_path:  # If host_path defined, host will be extracted from json event in send_jsonfile_to_splunk
                        record['host_path'] = host_path
                        
                    records.append(record)

                    # Update pattern match count for each matched artifact
                    for artifact in matched_artifacts:
                        self.pattern_match_count[artifact] += 1

                # Produce stats
                if not matched_artifacts:
                    self.no_match_count += 1
                if len(matched_artifacts) > 1:
                    self.multi_match_count += 1
                    file_pattern_matches[str(file_path)] = matched_artifacts

        return records

    def create_dataframe(self, input_dir):
        """
        Create a dataframe from scanned directories and save it to the disk or process it depending on test mode.

        Args:
            input_dir (str): The directory to scan and process.
        """
        # Check if input directory exists
        if not os.path.exists(input_dir):
            log.error(f"Input directory {input_dir} does not exist.")
            exit()
        records = self._scan_directory(input_dir)
        self.df = pl.DataFrame(records)

        # Write DF to disk if test mode
        if self.test_mode:
            directory = os.path.dirname(__file__)  # Gets the directory of the current script 
            relative_path = os.path.join(directory, "test_files_to_index.json")
            log.info(f"test mode - writing {relative_path} file.")
            absolute_path = os.path.abspath(relative_path)  
            self.df.write_json(absolute_path)  # Polars changed,  row-oriented  by default now

    def create_list_of_tuples(self):
        """
        Convert the dataframe into a list of tuples, each representing a file's details.
        """
        if not self.df.is_empty():
            selected_df = self.df[['file_path', 'sourcetype', 'host', 'timestamp_path', 'timestamp_format', 'host_path']]
        else:
            log.warning("It seems that the patterns matched nothing.")
            exit()  
        list_of_dicts = selected_df.to_dicts()
        self.list_of_tuples = list(tuple(d.values()) for d in list_of_dicts)

    def print_statistics(self):
        """
        Print statistics about file matches to the log.
        """
        log.info(f"Number of files that matched nothing: {self.no_match_count}")
        log.info(f"Number of files that matched multiple patterns: {self.multi_match_count}")
        for artifact, count in self.pattern_match_count.items():
            log.info(f"Number of files that matched pattern '{artifact}': {count}")

    
class Json2Splunk(object):
    """
    Ingest all matching files into Splunk. 
    Features auto create of index and HEC token.
    """

    def __init__(self):
        """
        Initializes an json2splunk instance, setting up placeholders for SplunkHelper
        and HTTP Event Collector server configurations.
        """
        self._sh = None
        self._hec_server = None
        self._is_test = False

    def configure(self, index: str, nb_cpu: int, testing: bool, config_spl: str):
        """
        Configures the instance with specified parameters to prepare for ingesting files into Splunk.

        Args:
            index (str): Index name where files will be pushed.
            nb_cpu (int): Number of CPUs to use for processing.
            testing (bool): If True, no data will be injected into Splunk (for testing purposes).
            config_spl (str): Configuration file path containing details for Splunk connection.

        Returns:
            bool: True if successfully configured, False otherwise.
        """
        # Load Splunk configuration file
        if config_spl == 'splunk_configuration.yml':
            directory = os.path.dirname(__file__)  # Gets the directory of the current script 
            relative_path = os.path.join(directory, config_spl)
            absolute_path = os.path.abspath(relative_path)  
            config_path = absolute_path
            config = load_yaml_config(config_path)
        else:
            config = load_yaml_config(config_spl)
        splunk_config = config['splunk']
        
        log.info(f"splunk configuration : {splunk_config}")

        self.nb_cpu = nb_cpu
        self._is_test = testing
        if self._is_test:
            log.warning("Testing mode enabled. NO data will be injected into Splunk")

        log.info("Init SplunkHelper")
        self._sh = SplunkHelper(splunk_url=splunk_config["host"],
                                splunk_port=splunk_config["mport"],
                                splunk_ssl_verify=splunk_config["ssl"] == "True",
                                username=splunk_config["user"],
                                password=splunk_config["password"])

        # The SplunkHelper instantiation holds a link_up
        # flag that indicated whether it could successfully reach
        # the specified SPlunk instance
        if self._sh.link_up:

            # Fetch or create the HEC token from Splunk
            hect = self._sh.get_or_create_hect()

            # Create a new index
            if self._sh.create_index(index=index):

                # Associate the index to the HEC token so the script can send
                # the logs to it
                self._sh.register_index_to_hec(index=index)

                # Instantiate HEC class and configure
                self._hec_server = http_event_collector(token=hect,
                                                        http_event_server=splunk_config["host"])
                self._hec_server.http_event_server_ssl = True
                self._hec_server.index = index
                self._hec_server.input_type = "json"
                self._hec_server.popNullFields = True

                return True

        return False
    
    def _detect_encoding(self, file_path, chunk_size=1024):
        """
        Get encoding type from a chunk of the file.

        Args
            file_path (str): Path of the file.
            chunk_size (int): Size of the chunk to read.
        Returns:
            str: Encoding name.
        """
        with open(file_path, 'rb') as file:
            raw_data = file.read(chunk_size)
            result = chardet.detect(raw_data)
            encoding = result['encoding']
            return encoding

    def _get_from_dict(self, dataDict: dict, mapList: list):
        """
        Get dict item from list of keys.

        Args
            dataDict (dict): Dict containg the item to extract
            mapList (list): List of keys to the item to extract
        Returns:
            str: value extracted of dataDict from the keys
        """
        try:
            value_extracted = reduce(operator.getitem, mapList, dataDict)
        except Exception as e:
            log.error(f"failed to extract the value from these keys: {mapList}. Error: {str(e)}")
            value_extracted = None
        return value_extracted

    def send_jsonfile_to_splunk(self, input_tuple: tuple):
        """
        Attempts to ingest a specified file into Splunk, adding sourcetype, host, timestamp_path, and timestamp_format details.

        Args:
            input_tuple (tuple): Tuple containing file_path, sourcetype, host, timestamp_path, timestamp_format.

        Returns:
            bool: True if the file was successfully ingested, False otherwise.
        """
        def process_records(record):
            epoch_time = self._extract_epoch_time(record, timestamp_path, timestamp_format) if timestamp_path else None
            host_from_path = self._get_from_dict(record, host_path.split('.')) if host_path else None
            payload["event"] = record
            if epoch_time:
                payload["time"] = epoch_time  
            if host_from_path:
                payload["host"] = host_from_path
            self._send_to_splunk(payload)

        file_path, sourcetype, host, timestamp_path, timestamp_format, host_path = input_tuple
        
        # Check if file is empty
        if os.stat(file_path).st_size == 0:
            log.debug(f"File {file_path} is empty.")
            return False

        try:
            file_extension = os.path.splitext(file_path)[1].lower()
            payload = {
                "source": file_path,
                "sourcetype": sourcetype,
                "host": host
            }
            
            if file_extension == '.json' or file_extension == '.jsonl':
                # Detect encoding for JSON files
                encoding = self._detect_encoding(file_path)
                
                with open(file_path, "r", encoding=encoding, errors='replace') as file_stream:
                    for record_line in file_stream:
                        try:
                            record = json.loads(record_line)
                            process_records(record)
                        except json.JSONDecodeError as e:
                            log.error(f"Record error in {file_path}. Error: {str(e)}")
                            continue

                    self._flush_splunk_batch()
                    return True

            elif file_extension == '.csv':
                # Detect encoding for CSV files
                encoding = self._detect_encoding(file_path)
                
                with open(file_path, "r", encoding=encoding, errors='replace') as file_stream:
                    file_stream = (line.replace('\x00', '') for line in file_stream)
                    csv_reader = csv.DictReader(file_stream)
                    for record_line in csv_reader:
                        try:
                            record = record_line
                            process_records(record)
                        except json.JSONDecodeError as e:
                            log.error(f"Record error in {file_path}. Error: {str(e)}")
                            continue

                    self._flush_splunk_batch()
                    return True
        except Exception as e:
            log.error(f"Failed to process file {file_path}. Error: {str(e)}")
            return False
        
    def _extract_epoch_time(self, record, timestamp_path, timestamp_format):
        try:
            timestamp = self._get_from_dict(record, timestamp_path.split('.'))
            if not timestamp:
                log.error(f"Timestamp {timestamp_path} has not been extracted from record {record}.")
                return None
            try:
                return datetime.strptime(timestamp, timestamp_format).timestamp()
            except Exception as e:
                log.error(f'Failed to convert timestamp {timestamp} with format {timestamp_format}. Error: {str(e)}. Trying auto mode...')
                try:
                    return parse(timestamp).timestamp()
                except Exception as e:
                    log.error(f'Failed to convert timestamp with auto mode. Error: {str(e)}.')
                    return None
        except Exception as e:
            log.error(f"Failed to extract timestamp. Error: {str(e)}")
            return None

    def _send_to_splunk(self, payload):
        if not self._is_test:
            self._hec_server.batchEvent(payload)
        else:
            log.debug(f"Test mode. Would have injected: {payload}")

    def _flush_splunk_batch(self):
        self._hec_server.flushBatch()

    def ingest(self, input_tuples: list):
        """
        Coordinates the multi-process ingestion of files into Splunk.

        Args:
            input_tuples (list): A list of tuples, each containing the file_path, sourcetype, and host.

        Returns:
            None: This method does not return anything.
        """
        start_time2 = time.time()
        log.info("Ingesting files started")
        with WorkerPool(n_jobs=self.nb_cpu, start_method='fork') as pool:
            list_of_tuples = [(item,) for item in input_tuples]
            for result in pool.imap(self.send_jsonfile_to_splunk, list_of_tuples):
                pass
        
        end_time2 = time.time()
        log.info(f"Ingesting finished in {end_time2 - start_time2:.2f} seconds")


def load_yaml_config(filepath):
    """Load a YAML configuration file."""
    try:
        with open(filepath, 'r') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        log.error(f"Error: The file '{filepath}' does not exist.")
        exit()
    except yaml.YAMLError as exc:
        log.error(f"Error parsing YAML file: {exc}")
        exit()

    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbosity", help="increase output verbosity", choices=LOG_VERBOSITY, default='INFO')

    parser.add_argument('--input', required=True, help="Directory to index")

    parser.add_argument('--nb_cpu', type=int, default=cpu_count(),
                        help=f"Number of CPUs to spawn, only useful for more than 1 file. Default value is {cpu_count()}")

    parser.add_argument('--index', required=True, default="json2splunk", help="index to use for ingest process")

    parser.add_argument('--test', action="store_true",
                        help="Testing mode. No data is sent to Splunk but index and HEC token are created. \
                            Dataframe containing matches files is created for debugging purpose.")

    parser.add_argument('--config_spl', help="Splunk config file. Default is splunk_configuration.yml.", default='splunk_configuration.yml')
    
    parser.add_argument('--indexer_patterns', help="Configuration for files pattern definition. Default is indexer_patterns.yml.", default='indexer_patterns.yml')

    args = parser.parse_args()
    
    log.basicConfig(format=LOG_FORMAT, level=LOG_VERBOSITY[args.verbosity], datefmt='%Y-%m-%d %I:%M:%S')
    # log.getLogger("urllib3").setLevel(log.WARNING)
    start_time = time.time()
    log.info(f"Nb of CPUs : {args.nb_cpu}")
        
    # Build dataframe with all files to index    
    file_matcher = FileMatcher(args.indexer_patterns, args.test)
    file_matcher.create_dataframe(args.input)
    file_matcher.print_statistics()
    # Extract tuples ('file_path', 'sourcetype', 'host', 'timestamp_path', 'timestamp_format')
    file_matcher.create_list_of_tuples()
    
    input_identification_end_time = time.time()
    log.info(f"Input identification finished in {input_identification_end_time - start_time:.3f} seconds")

    # Start indexing files    
    j2s = Json2Splunk()
    if j2s.configure(index=args.index, nb_cpu=args.nb_cpu, testing=args.test, config_spl=args.config_spl):
        j2s.ingest(input_tuples=file_matcher.list_of_tuples)
    end_time = time.time()

    log.info(f"Finished in {end_time - start_time:.2f} seconds")
    
# curl -k  https://host.docker.internal:8089/services/data/inputs/http

