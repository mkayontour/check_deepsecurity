#!/usr/bin/perl
#
# Trend Micro Deep Security 9.5 - Icinga check plugin
#
# COPYRIGHT:
#
# This software is Copyright (c) 2015 NETWAYS GmbH, Alexander Fuhr
# 				<support@netways.de>
# This software is Copyright (c) 2015 NETWAYS GmbH, Dirk Goetz
# 				<support@netways.de>
#
# LICENSE:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
# or see <http://www.gnu.org/licenses/>.
#
# CONTRIBUTION SUBMISSION POLICY:
#
# (The following paragraph is not intended to limit the rights granted
# to you to modify and distribute this software under the terms of
# the GNU General Public License and is only of importance to you if
# you choose to contribute your changes and enhancements to the
# community by submitting them to NETWAYS GmbH.)
#
# By intentionally submitting any modifications, corrections or
# derivatives to this work, or any other work intended for use with
# this Software, to NETWAYS GmbH, you confirm that
# you are the copyright holder for those contributions and you grant
# NETWAYS GmbH a nonexclusive, worldwide, irrevocable,
# royalty-free, perpetual, license to use, copy, create derivative
# works based on those contributions, and sublicense and distribute
# those contributions and any derivatives thereof.

##############################################################################
# INCLUDES
##############################################################################

use strict;
use warnings;

use SOAP::Lite;
use Getopt::Long;
use DateTime;
use DateTime::Format::Strptime qw();

use Data::Dumper;

##############################################################################
# INTERNAL VARS
##############################################################################

my $VERSION = '0.1';

##############################################################################
# ALARM STATES DETECTION
##############################################################################

my @states_critical = (
	'Anti-Malware Engine Offline',
	'Offline',
	'Unable to communicate',
);

my @states_warning = (
	'Unmanaged (VM Stopped)',
	'Unprepared',
	'Unmanaged (No Agent)',
	'Unmanaged (Unknown)',
	'Upgrade Recommended',
	'Virtual Machine Moved to Unprotected ESX',
	'Unmanaged (Offline)'
);

my @malware_states_critical = (
	'research',
);

my @malware_states_warning = (
	'Not Activated',
);

##############################################################################
# DECLARE THE HELP
##############################################################################

my $HELP = <<'HELP';
Trend Micro Deep Security 9.5 - Icinga check plugin

This plugin provides checks to retrieve the state summary
and a single host state by the provided displayName and the
summary of the antimalware events of the last day.

Options:

	--mode							(status|antimalware) required
	--host							(displayName of the host) required in case to retrieve the host status
	--user							(username) required
	--pass							(password) required
	--wsdl							(the url to the wsdl of the deep security manager) required
	--unmanaged_warning (number) when using mode status warning threshold for unmanaged agents
	--unmanaged_critical(number) when using mode status critical threshold for unmanaged agents
	--version						(version)
	--help							(help)
	--debug							(print soap call all status informations)

Usage:

	To retrieve the state summary of all hosts use the --mode=status without the --host option.

	e.g. $ perl deepsecurity_check.pl --mode status --user <user> --pass <pass> --wsdl <url>

	To retrieve the single host status of a specific host use the --host option together with the --mode option.

	e.g. $ perl deepsecurity_check.pl --mode status --host <displayName> --user <user> --pass <pass> --wsdl <url>

	To retrieve the state summary of all antiware events in the last day use the --mode=antimalware without the --host option.

	e.g. $ perl deepsecurity_check.pl --mode antimalware --user <user> --pass <pass> --wsdl <url>

HELP

##############################################################################
# PROVIDE OPTIONS
##############################################################################

my $opts;

GetOptions(
	'mode=s'     => \$opts->{mode},
	'host=s'     => \$opts->{host},
	'user=s'     => \$opts->{user},
	'pass=s'     => \$opts->{pass},
	'wsdl=s'     => \$opts->{wsdl},
	'unmanaged_warning=s' => \$opts->{uwarning},
	'unmanaged_critical=s'=> \$opts->{ucritical},
	'version'    => \$opts->{version},
	'help'	     => \$opts->{help},
	'debug'	     => \$opts->{debug},
);

if (defined $opts->{version}) {
	print $VERSION . "\n";
	exit 0;
}

if (defined $opts->{help}) {
	print $HELP . "\n";
	exit 0;
}

##############################################################################
# CHECK OPTIONS
##############################################################################

if (not defined $opts->{mode}) {
	print "Option --mode not specified.\n";
	exit 3;
}
if (not defined $opts->{user}) {
	print "Option --user not specified.\n";
	exit 3;
}
if (not defined $opts->{pass}) {
	print "Option --pass not specified.\n";
	exit 3;
}
if (not defined $opts->{wsdl}) {
	print "Option --wsdl not specified.\n";
	exit 3;
}

##############################################################################
# RETRIEVE THE SOAP SID
##############################################################################

$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;
my $service = SOAP::Lite->service($opts->{wsdl});
my $sid = $service->authenticate($opts->{user}, $opts->{pass});

sub closeSession {
	$service->endSession($sid);
}

##############################################################################
# RETRIEVE THE STATE SUMMARY
##############################################################################

if (($opts->{mode} eq "status")&&(not defined $opts->{host})) {

	my $response = $service->statusSummaryRetrieve($sid);
	my $s;

	$s->{'c'} = ${$response}{'hostStatusSummary'}{'criticalHosts'};
	$s->{'w'} = ${$response}{'hostStatusSummary'}{'warningHosts'};
	$s->{'m'} = ${$response}{'hostStatusSummary'}{'onlineHosts'};
	$s->{'u'} = ${$response}{'hostStatusSummary'}{'unmanageHosts'};

	my $output = "Critical ".$s->{c}.", Warning ".$s->{w}.", Managed ".$s->{m}.", Unmanaged ".$s->{u};
	my $perf = "critical=".$s->{c}." warning=".$s->{w}." managed=".$s->{m}." unmanaged=".$s->{u};



	closeSession();

	if ( defined $opts->{ucritical} ) {
		if ( $s->{u} > $opts->{ucritical} ) {
			$output = "Unmanaged ".$s->{u}.", Critical ".$s->{c}.", Warning ".$s->{w}.", Managed ".$s->{m};
			print "Critical Computer Status: " . $output . " | " . $perf . "\n";
			exit 2;
		}
	}
	if ( defined $opts->{uwarning} ) {
		if ($s->{u} > $opts->{uwarning} ) {
			$output = "Unmanaged ".$s->{u}.", Critical ".$s->{c}.", Warning ".$s->{w}.", Managed ".$s->{m};
			print "Warning Computer Status: " . $output . " | " . $perf . "\n";
			exit 1;
		}
	}

	if ( $s->{c} > 0 ) {
		$output = "Critical ".$s->{c}.", Warning ".$s->{w}.", Managed ".$s->{m}.", Unmanaged ".$s->{u};
		print "Critical Computer Status: " . $output . " | " . $perf . "\n";
		exit 2;
	}
	if ($s->{w} > 0 ) {
		$output = "Critical ".$s->{c}.", Warning ".$s->{w}.", Managed ".$s->{m}.", Unmanaged ".$s->{u};
		print "Warning Computer Status: " . $output . " | " . $perf . "\n";
		exit 1;
	}

  print "Computer Status: " . $output . " | " . $perf . "\n";
	exit 0;
}

##############################################################################
# RETRIEVE THE HOST STATE
##############################################################################

if (($opts->{mode} eq "status")&&(defined $opts->{host})) {

	my $host = $opts->{host};

	sub getAllHosts {
		my %data;

		foreach my $r ($service->hostRetrieveAll($sid)) {
			if (${$r}{'displayName'} eq "") {
				next;
			} else {
				$data{${$r}{'displayName'}} = ${$r}{'ID'};
			}
		}

		return %data;
	}

	my %hosts = getAllHosts();

	my $hostId = "";

	if (defined $hosts{$host}) {
		$hostId = $hosts{$host};
	}

	if ($hostId eq "") {
		print "WARNING: Host " . $host . " could not be found\n";
		exit 1;
		closeSession();
	}

	my $status = $service->hostGetStatus($hostId, $sid);
	my $state = ${$status}{'protectionStatusTransports'}{'item'}{'status'};
	my $malwareState = ${$status}{'protectionStatusTransports'}{'item'}{'antiMalwareStatus'};

	if (defined $opts->{debug}) {
		print "Host ID: " . $hostId . "\n";
		print "Status Informations:\n";
		print Dumper $status;
	}

	my $malwareStatusString;

	if ($malwareState eq "") {
		$malwareStatusString = "";
	} else {
		$malwareStatusString = " and malware status " . $malwareState;

		if (grep { $_ eq $malwareState} @malware_states_critical) {
			my $output = "Host " . $host . " (ID:" . $hostId . ") with host status " . $state . $malwareStatusString;

			print "CRITICAL: " . $output . "\n";

			closeSession();
			exit 2;
		}

		if (grep { $_ eq $malwareState } @malware_states_warning) {
			my $output = "Host " . $host . " (ID:" . $hostId . ") with host status " . $state . $malwareStatusString;

			print "WARNING: " . $output . "\n";

			closeSession();
			exit 1;
		}
	}

	if (grep { $_ eq $state} @states_critical) {
		my $output = "Host " . $host . " (ID:" . $hostId . ") with host status " . $state . $malwareStatusString;

		print "CRITICAL: " . $output . "\n";

		closeSession();
		exit 2;
	}

	if (grep { $_ eq $state } @states_warning) {
		my $output = "Host " . $host . " (ID:" . $hostId . ") with host status " . $state . $malwareStatusString;

		print "WARNING: " . $output . "\n";

		closeSession();
		exit 1;
	}

	print "OK: Host " . $host . " (ID:" . $hostId . ") with host status: " . $state . $malwareStatusString . "\n";

	closeSession();

	exit 0;

}

##############################################################################
# RETRIEVE THE STATE SUMMARY
##############################################################################

if (($opts->{mode} eq "antimalware")&&(not defined $opts->{host})) {

	my $response = $service->antiMalwareEventRetrieve('','','',$sid);
	my @events = ();
	my $cleaned = 0;
	my $denied = 0;
	my $deleted = 0;
	my $passed = 0;
	my $quarantined = 0;
	my $uncleanable = 0;

	foreach my $item (@{${$response}{'antiMalwareEvents'}{'item'}}) {
		my $p = DateTime::Format::Strptime->new(pattern => '%Y-%m-%dT%H:%M:%S', on_error => 'croak',);
		my $logdate = $p->parse_datetime(${$item}{logDate});
		my $maxdate = DateTime->now()->subtract(days => 1);
		if ($logdate > $maxdate) {
			push(@events, $item);
			if (${$item}{'summaryScanResult'} eq "Cleaned") {
				$cleaned += 1;
			} elsif (${$item}{'summaryScanResult'} eq "Deny Access") {
				$denied += 1;
			} elsif (${$item}{'summaryScanResult'} eq "Deleted") {
				$deleted += 1;
			} elsif (${$item}{'summaryScanResult'} eq "Passed") {
				$passed += 1;
			} elsif (${$item}{'summaryScanResult'} eq "Quarantined") {
				$quarantined += 1;
			} elsif (${$item}{'summaryScanResult'} eq "Uncleanable") {
				$uncleanable += 1;
			}
		}
	}

	my $count = $#events+1;
	my $output = "";
	my $state = 0;

	if ($count == 0) {
		$output = "OK: No Antimalwareevent in the last day";
	} else {
		$output = "CRITICAL: $count Antimalwareevent in the last day";
		$state = 2;
	}

	my $perfdata = "cleaned=$cleaned denied=$denied deleted=$deleted passed=$passed quarantined=$quarantined uncleanable=$uncleanable";

	print $output . " | " . $perfdata . "\n";

	closeSession();

	exit $state;
}
