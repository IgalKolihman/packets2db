# Packets2DB

`packets2db` is a Python package that allows you to store packets in various types of
storage and databases. It is built on top of the popular packet manipulation library
scapy, making it easy to integrate into your existing packet analysis workflow.
`packets2db` is installable via pip, and requires a configuration file to operate.

# Installation

To install packets2db, simply run:

```bash
pip install packets2db
```

# Usage

`packets2db` requires a configuration file (`.ini` type) to operate. Here's an example
configuration file:

```ini
[STORAGE]
type = pcap
path = my_packets.pcap

[SNIFFER]
interface = Wi-Fi
logging = v
only_layers =
    IP
exclude_layers =
    Raw
    Ethernet
```

The configuration file has two sections:

* `[STORAGE]`: Specifies the type of storage to use.
* `[SNIFFER]`: Specifies the network interface to capture packets from, the logging
  level, and what layers to include or exclude.

## command-line interface

It is possible to run `packets2db` from the command-line interface (CLI) after
installing it via `pip`.

```bash
packets2db -c path/to/config.ini
```

The CLI provides the ability to run the sniffer on a specific interface and send the
packets to the selected storage.

The `-c` or `--config` option allows the user to specify a custom path for the
configuration file. If the option is not used, the default configuration file is located
at `./.packets2db.ini`. The configuration file specifies the interface to sniff on, the
database to use, and any optional filtering parameters.

For more help, simply run:

```bash
packets2db --help
```

## Supported storage options

`packets2db` supports the following storage options:

| Storage type | Parameters                                                                                                                                                           |
|--------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| pcap         | `type`: Type of storage, must be set to `pcap`. <br> `path`: Path where the `.pcap` file will be stored.                                                             |
| mongodb      | `type`: Type of storage, must be set to `mongodb`. <br> `url`: Connection URL for the MongoDB server. <br> `collection`: Name of the collection to store packets in. |

# Contributing

If you find a bug or would like to suggest a new feature, please open an issue for this
repository. If you would like to contribute code, please submit a pull request.
