# json2splunk

`json2splunk` is a Python script designed to process and ingest JSON formatted log files into Splunk. This script leverages multiprocessing to efficiently handle multiple files and integrates with Splunk's HTTP Event Collector (HEC) to push data.



## Features

- **CSV files**: Supports also csv files.
- **Multiprocessing Support**: Utilizes multiple CPUs to process files concurrently with mpire lib (https://github.com/sybrenjansen/mpire).
- **Flexible File Matching**: Configurable file matching rules based on file name patterns and path suffixes, allowing selective processing of files.
- **Splunk Integration**: Automates the creation of Splunk indices and HEC tokens, ensuring that data is ingested smoothly and efficiently into Splunk.
- **Test Mode**: Allows running the script in a test configuration where no data is actually sent to Splunk, useful for debugging and validation.

## Requirements

- Run only on `Linux host`
- Python 3.7 or newer
- External libraries: `argparse`, `json`, `logging`, `os`, `re`, `time`, `datetime`, `functools`, `multiprocessing`, `pathlib`, `polars`, `yaml`, `mpire`, `splunk_http_event_collector`
- `splunk_http_event_collector` modified to remove multithreading as `json2splunk` is already using multiprocessing 

## Setup

1. **Clone the repository**:
   ```
   git clone https://github.com/maxspl/json2splunk.git
   cd json2splunk
   ```

2. **Install required Python libraries**:
   ```
   pip install -r requirements.txt
   ```

3. **Configure Splunk Settings**:
   Update `splunk_configuration.yml` with your Splunk instance details:
   ```yaml
   splunk:
     host: {splunk_FQDN_or_IP}
     user: {splunk_user}
     password: {splunk_password}
     port: {splunk_port} # Default is 8000
     mport: {splunk_mport} # Default is 8089
     ssl: {splunk_enable_ssl} # Default is False
   ```

4. **Set File Matching Rules**:
   Edit `indexer_patterns.yml` to define the patterns for the files you want to ingest:
   ```yaml
   evtx:
     name_rex: # regex matching the file name (optional if path_suffix is set)
     path_suffix: # suffix path to files to index (optional if path_suffix is set). Match ending path. Ex: If "path_suffix: evtx" will match of files ending wih .jsonl under <whatever is the path>/evtx/
     sourcetype: # Splunk sourcetype (optional)
     timestamp_path: # path to the json key containing the event timestamp. Populates Splunk _time field. Ex: "Event.System.TimeCreated.#attributes.SystemTime"  (optional)
     timestamp_format: # format of the timestamp extracted. Ex: "%Y-%m-%dT%H:%M:%S.%fZ" (optional)
     host_path: # path to the json key containing the event host. Populates Splunk host field. Ex: Event.System.Computer (optional)
     host_rex: # regex to extract the hostname for the filename. Populates Splunk host field. (optional)
   ```

## Usage

Run the script with the required parameters. Example usage:

```bash
python json2splunk.py --input /path/to/logs --index my_index
python json2splunk.py --input /path/to/logs --index my_index --config_spl /opt/json2splunk/splunk_configuration.yml --indexer_patterns /opt/json2splunk/indexer_patterns.yml
python json2splunk.py --input /path/to/logs --index my_index --nb_cpu 4
```

### Parameters

- `--input`: Mandatory. Directory containing the log files to process.
- `--index`: Mandatory. The name of the Splunk index to use.
- `--nb_cpu`: Optional. Specifies the number of CPUs to use for processing. Defaults to the number of available CPUs.
- `--test`: Optional. Enables test mode where no data is sent to Splunk. Useful for debugging.
- `--config_spl`: Optional. Specifies the path to the Splunk configuration file. Defaults to `splunk_configuration.yml`.
- `--indexer_patterns`: Optional. Specifies the path to the file patterns configuration. Defaults to `indexer_patterns.yml`.

### Test Mode

Test mode is designed to validate the setup without pushing data to Splunk. It simulates the entire process, from file scanning to data preparation, without making any actual data transmissions to Splunk. 

This mode also generates a dataframe (named test_files_to_index.json) containing matched files and patterns, which can be reviewed to ensure correct file handling before live deployment.

For example, the dataframe can be used to review the patterns matched by each file: 

```json
[
  {
    "file_path": "input_sample/prefetch/SRV-DA09DKL--prefetch-AA4646DB4646A841_2000000016FC0_D000000018CE8_4_TABBY.EXE-D326E1BD.pf_{00000000-0000-0000-0000-000000000000}.data.jsonl",
    "file_name": "SRV-DA09DKL--prefetch-AA4646DB4646A841_2000000016FC0_D000000018CE8_4_TABBY.EXE-D326E1BD.pf_{00000000-0000-0000-0000-000000000000}.data.jsonl",
    "artifact_name": [
      "prefetch",
      "all"
    ],
    "sourcetype": "_json",
    "timestamp_path": "",
    "timestamp_format": "",
    "host": "SRV-DA09DKL",
    "host_path": null
  },
  {
    "file_path": "input_sample/evtx/SRV-DA09DKL--evtx-AA4646DB4646A841_10000000014B3_E0000000249F8_4_Microsoft-Windows-StorageSettings%4Diagnostic.evtx_{00000000-0000-0000-0000-000000000000}.data.jsonl",
    "file_name": "SRV-DA09DKL--evtx-AA4646DB4646A841_10000000014B3_E0000000249F8_4_Microsoft-Windows-StorageSettings%4Diagnostic.evtx_{00000000-0000-0000-0000-000000000000}.data.jsonl",
    "artifact_name": [
      "evtx",
      "all"
    ],
    "sourcetype": "_json",
    "timestamp_path": "Event.System.TimeCreated.#attributes.SystemTime",
    "timestamp_format": "%Y-%m-%dT%H:%M:%S.%fZ",
    "host": "Unknown", // Normal as host_path is extracted after the dataframe creation
    "host_path": "Event.System.Computer"
  }
]
``` 

# Example 

### Directory Structure Example

Let's ingest these files:

```
/input_sample
├── output
│   ├── app
│   │   ├── error
│   │   │   └── app_error.jsonl
│   │   ├── info
│   │   │   └── app_info.jsonl
│   │   └── debug
│   │       └── app_debug.jsonl
├── prefech
│   ├── HOST-A--prefetch1.jsonl
│   ├── HOST-A--prefetch2.jsonl
│   └── HOST-A--prefetch3.jsonl
└── evtx
    ├── event1.jsonl
    ├── event2.jsonl
    └── event3.jsonl
```

### Patterns Configuration (`indexer_patterns.yml`)

This YAML file is crucial for specifying which files `json2splunk.py` should process. You can define multiple criteria based on file name regex patterns and path suffixes:
Each entry specifies a unique pattern to match certain files with specific processing rules for Splunk ingestion.

**Warning:** Fields required: sourcetype, one of: name_rex, path_suffix
**Warning:** If a file matches several artifacts, the first one is selected.

```yaml
evtx:
    name_rex: \.jsonl$
    path_suffix: evtx
    sourcetype: _json
    host_path: "Event.System.Computer" # Extract the host from the event
    timestamp_path: "Event.System.TimeCreated.#attributes.SystemTime" # Extract the timestamp from the event
    timestamp_format: "%Y-%m-%dT%H:%M:%S.%fZ" # Specify the timestamp format
prefetch:
    name_rex: \.jsonl$
    path_suffix: prefetch
    sourcetype: _json
    host_rex: (^[\w-]+)-- # Extract the host from the filename
    timestamp_path: LastRun # Extract the timestamp from the event
    timestamp_format: "%Y-%m-%d %H:%M:%S" # Specify the timestamp format
application:
    path_suffix: output/app
    sourcetype: _json
    host_rex: (^[\w-]+)--
hives:
    name_rex: \.csv$
    path_suffix: hives
    sourcetype: _json
    host_rex: (^[\w-]+)--
```

### Run the script

```bash
python json2splunk.py --input /input_sample --index my_index
```

