# FortiGate configuration to HTML format
Some sort of tools for analysing FortiGate firewall configuration and exporting to HTML format.

## Notes
* It will just process configuration files in text format.
* Tested only with FortiGate version 5.0.x

## Features
* Explodes address, service and group objects.
* Finds duplicate address objects.
* Explodes firewal policies.
* Explodes IPSec phase-1/2 configurations.
* Creates single HTML file without any dependency.

## Requirements
* php >= 5.5

## Usage
Download FortiGate configuration from the device and run as follows;

	> php ./fgtohtml.php fortigate-config-file.conf

This creates a new version of the original file with .html extension.

### Trademarks
Products and Brands mentioned in this project are trademarks or registered trademarks of their respective holders.

#### Enjoy!
