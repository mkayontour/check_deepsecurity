check_deepsecurity
==================

Trend Micro Deep Security 9.5 - Icinga check plugin

This plugin provide checks to retrieve the state summary and a single host state by the provided displayName.

### Requirements

* Perl libraries: `SOAP::Lite`
* Perl libraries: `DateTime`
* Perl libraries: `DateTime::Format::Strptime`

### Usage

To retrieve the state summary of all hosts use the --mode=status without the --host option.

e.g. $ perl deepsecurity_check.pl --mode status --user <user> --pass <pass> --wsdl <url>

To retrieve the single host status of a specific host use the --host option together with the --mode option.

e.g. $ perl deepsecurity_check.pl --mode status --host <displayName> --user <user> --pass <pass> --wsdl <url>

To retrieve the state summary of all antiware events in the last day use the --mode=antimalware without the --host option.

e.g. $ perl deepsecurity_check.pl --mode antimalware --user <user> --pas

### Options
    --mode		(status|antimalware) required
    --host		(displayName of the host) required in case to retrieve the host status
    --user		(username) required
    --pass		(password) required
    --wsdl		(the url to the wsdl of the deep security manager) required
    --version	(version)
    --help		(help)
    --debug		(print soap call all status informations)

### Note

Please keep the check interval in larger intervals to prevent an overload of the api instance.

