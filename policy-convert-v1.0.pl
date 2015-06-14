#!/usr/bin/perl

# Usage:
# 	If the rule -> interface mapping CSV has been generated already, generate the converted config with:
#		policy-convert.pl <policy xml file> <service xml file> <network xml file> <rule-interface mapping csv> <FW name>
#	If the rule -> interface mapping CSV still needs to be created, create it with:
#		policy-convert.pl -csv <policy xml file> <network xml file> <FW name>
#
# This script does not successfully convert all rules properly. The following types of rules will be converted, but not 
# properly:
# - Time based access rules
#		* This can be done on ASA, but will need to be done manually.
# - Rules that say "NOT (object)" e.g. Permit all traffic from internal networks that is a approved-internet-port and is NOT
#   destined for a private network.
#		* The ASA does not support negatively referencing a src/dest object. In order to fix this, you will need to manually
#		  create the rule referencing the inverse destination.

use Data::Dumper qw(Dumper);

my ($sec, $min, $hr, $day, $mon, $year) = localtime;
my $timestamp = sprintf("%02d%02d%04d_%02d%02d%02d", $mon + 1, $day, 1900 + $year, $hr, $min, $sec); 

if ($#ARGV != 4) {
	if( $ARGV[0] == '-csv' and $#ARGV == 3 ) {
		# Use this portion to build the CSV file that can then be used to create the csv for mapping rules to interfaces.
		# This will only run if the -csv option is used in the command line.
		
		my $csv = $ARGV[0];
		my $policyfile = $ARGV[1];
		my $netfile = $ARGV[2];
		my $FW = $ARGV[3];
		my $csv = "$FW-Security-Policy-$timestamp.csv";
		
		# Build network objects for display of IPs in the CSV file.
		open NETWORK, $netfile or die "Couldn't open $netfile for reading, $!.\n";
		
		my %networks;
		while(<NETWORK>) {
			my @networks;
			(@networks) = $_ =~ /<network_object>.*?<\/network_object>/g;
			foreach my $network (@networks) {
				# Clear out variables.
				my ($name, $class, $type, $ip, $mask, $fqdn, $comm) = undef;
		
				($name)  = $network =~ /<Name>(.*?)<\/Name>/;
				($class) = $network =~ /<Class_Name>(.*?)<\/Class_Name>/;
				($type)  = $network =~ /<type><!\[CDATA\[(.*?)\]\]><\/type>/;
				($ip)	 = $network =~ /<ipaddr><!\[CDATA\[(.*?)\]\]><\/ipaddr>/;	# This value doesn't exist in all classes.
				($mask)	 = $network =~ /<netmask><!\[CDATA\[(.*?)\]\]><\/netmask>/;	# This value doesn't exist in all classes.
				($fqdn)  = $network =~ //;
				($comm)  = $network =~ /<comments><!\[CDATA\[(.*?)\]\]><\/comments>/;

				# If it's not a legitimate class, skip it.
				next if( $class !~ m/[host_plain|network_object_group|network]/ );
		
				# Put values in global multidimensional hash.
				$networks{$name}{name}	= $name;
				$networks{$name}{class} = $class;
				$networks{$name}{type}  = $type;
				$networks{$name}{ip}	= $ip;
				$networks{$name}{mask}  = $mask;
				$networks{$name}{fqdn}  = $fqdn;
				$networks{$name}{comment} = $comm;
				
				#print "$networks{$name}{ip}\n"
			}
		}

		open CSV, ">$csv" or die "\nCouldn't open $outfile for writing, $!.\n";
		print CSV "Rule Num,Interface,Action,Source,Destination,Service,Comment\n";
		
		open POLICY, $policyfile or die "Could not open $policyfile, $!.\n";
		while(<POLICY>) {
			(@rules) = $_ =~ /<rule><Name><\/Name>\s*<Class_Name>security_rule<\/Class_Name>.*?<action><Name>[a-zA-Z]*?<\/Name>.*?<\/rule>/g;
		  	foreach my $x (@rules) {
			    ($rnum) = $x =~ /<Rule_Number>([0-9]+)<\/Rule_Number>/;
			    ($action) = $x =~ /<action><Name>([a-zA-Z]+)<\/Name>/;
			    ($comment) = $x =~ /<comments><!\[CDATA\[(.*?)\]\]/;
			    print CSV "$rnum,,$action,";
		
				##############
				# Sources
				##############
			    ($src) = $x =~ /(<src>.*?<\/src>)/;
			    (@srcs) = $src =~ /<Name>(.*?)<\/Name>/g;

			    print CSV "\"";
			    foreach my $y (@srcs) {
					#print "IP:$networks{$y}{ip}\n";
			      	if ($y =~ /[0-9a-zA-Z]+/) {
			        	print CSV "$y\r";
						print CSV "This is a network group.\r" if $networks{$y}{type} =~ m/group/;
						print CSV "Comment: $networks{$y}{comment}\r" if $networks{$y}{comment} != '';
						print CSV "IP: $networks{$y}{ip}" if defined $networks{$y}{ip};
						print CSV " - Mask: $networks{$y}{mask}" if defined $networks{$y}{mask};
						print CSV "\r\r";
			      	}
			    }
			    print CSV "\",";
		
				##############
				# Destinations
				##############
			    ($dest) = $x =~ /(<dst>.*?<\/dst>)/;
			    (@dests) = $dest =~ /<Name>(.*?)<\/Name>/g;

			    print CSV "\"";
			    foreach my $y (@dests) {
			      	if ($y =~ /[0-9a-zA-Z]+/) {
			        	print CSV "$y\r";
						print CSV "This is a network group.\r" if $networks{$y}{type} =~ m/group/;
						print CSV "Comment: $networks{$y}{comment}\r" if $networks{$y}{comment} != '';
						print CSV "IP: $networks{$y}{ip}" if defined $networks{$y}{ip};
						print CSV " - Mask: $networks{$y}{mask}" if defined $networks{$y}{mask};
						print CSV "\r\r";
			      	}
			    }
			    print CSV "\",";
		
				##########
				#Services
				##########
			    ($service) = $x =~ /(<services>.*?<\/services>)/;
			    (@services) = $service =~ /<Name>(.*?)<\/Name>/g;
	
			    print CSV "\"";
			    foreach my $y (@services) {
			      	if ($y =~ /[0-9a-zA-Z]+/) {
			        	print CSV "$y\r";
			    	}
			    }
		
			    print CSV "\",$comment\n";
		  	}
		}

		print "The CSV $csv has been created.\n\nPlease use the file to map each rule to an interface name in the provided 'interface' column. If you want the rule to be ignored during conversion, label it with 'remove'.\n\n";
	} else {
		print "If the rule -> interface mapping CSV has been generated already, generate the converted config with:\n";
	  	print "\tUsage: policy-convert.pl <policy xml file> <service xml file> <network xml file> <rule-interface mapping csv> <FW name>\n";
		print "If the rule -> interface mapping CSV still needs to be created, create it with:\n";
		print "\tUsage: policy-convert.pl -csv <policy xml file> <networks xml file> <FW name>\n";
	}
	exit;
} 

my $policyfile = $ARGV[0];
my $svcfile = $ARGV[1];
my $netfile = $ARGV[2];
my $intfile = $ARGV[3];
my $FW = $ARGV[4];

print "The following configuration file is being created:\n";
print "\tConfiguration file: $FW-config-$timestamp.cfg\n\n";
print "Please review the outputted configuration for accuracy before applying it.\n";
# Text file for the config that is built.
open CONFIG, ">$FW-config-$timestamp.cfg";
print CONFIG "! Configuration file for $FW firewall.\n! Built on $timestamp.\n! Contains service objects, network objects, and security policy.\n\n";

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Open CSV file to identify which interface the rule will be applied to.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
open FH, $intfile or die "Couldn't open $intfile for reading, $!.\n";

my %int;

while(<FH>) {
	my %rules;
	if( $_ =~ m/\s+[0-9]+,[a-zA-Z ]+,.*?/ ) {
		while( $_ =~ /\s+([0-9]+),([a-zA-Z ]+),.*?/g )
		{
			$int{$1} = $2;
			# $int{$1} =~ tr/[A-Z]/[a-z]/;
		}
	} elsif( $_ =~ m/^[0-9]+,[a-zA-Z ]+.*/ ) {
		while( $_ =~ /^([0-9]+),([a-zA-Z ]+).*/g )
		{
			$int{$1} = $2;
			# $int{$1} =~ tr/[A-Z]/[a-z]/;
		}	
	} else {
		die "ERROR: Can't read formatting of rule-interface mapping file. Quitting..\n";
	}
}
close FH;


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Build rules array from service policy xml
# Will be put into a global hash that can be referenced with $services{'name'}{[key]}.
# Below is the structure of the hash:
# %rules = {
# 	$rnum => {
#		'rnum' => $rnum,
# 		'name' => "$interface-acl", 
# 		'interface' => $interface,
# 		'action' => $asa_action,
# 		'src' => $rule_src,
# 		'dest' => $rule_dest,
# 		'services' => $rule_service,
# 		'disabled' => $disabled,
# 		'type' => $type,
# 		'comment' => $comment
# 	},
# };
# Ex: $rules{'1'}{src} would return the src network(s) of rule 1 either as a single 
# 	  item or a list of comma seperated values. In the case of a list of CSVs, we will
#     then have to go on to identify what group they belong to since the ASA reference
#	  the name of the object group instead of each member object.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

my (%inpolicy, %rules);

open POLICY, $policyfile or die "Couldn't open $policyfile for reading, $!.\n";
while(<POLICY>) {
	my @rules;
	# Pull one rule entry.
    (@rules) = $_ =~ /<rule><Name><\/Name>\s*<Class_Name>security_rule<\/Class_Name>.*?<action><Name>[a-zA-Z]*?<\/Name>.*?<\/rule>/g;
    foreach my $rule (@rules) {
		# Reset variables
		my ($rnum, $action, $asa_action, $comment, $src, $dest, $service, $disabled, $rule_src, $rule_dest, $rule_service, $type, $interface, $inttwo, $dup_rule) = undef;
		my (@srcs, @dests, @services);
		
		($rnum) = $rule =~ /<Rule_Number>([0-9]+)<\/Rule_Number>/;
		# Interface rule will be applied on
		if ( $int{$rnum} =~ m/([a-z]+)\sand\s([a-z]+)/ ) {
			# If the CSV contained two interfaces, set the $dup_rule flag to 1 and list the second interface.
			# The rule is duplicated by adding 1000 to the rule number later in the script.
			# Must be in the format: "inside and outside"
			$int{$rnum} =~ /([a-zA-Z]+)\sand\s([a-zA-Z]+)/;
			$interface = $1;
			$inttwo = $2;
			$dup_rule = 1;
		} else {
			$interface = $int{$rnum};
		}
		# Skip if marked for removal.
		next if( $interface =~ m/remove/ );
		# Rule action
		($action) = $rule =~ /<action><Name>([a-zA-Z]+)<\/Name>/;
		# Convert to ASA syntax
		$asa_action = ($action =~ m/accept/) ? 'permit' : 'deny';
		# Rule description
		($comment) = $rule =~ /<comments><!\[CDATA\[(.*?)\]\]/;
		# Source / Source Objects
		($src) = $rule =~ /(<src>.*?<\/src>)/;
		(@srcs) = $src =~ /<Name>(.*?)<\/Name>/g;
		# Destination / Destination ojects
		($dest) = $rule =~ /(<dst>.*?<\/dst>)/;
		(@dests) = $dest =~ /<Name>(.*?)<\/Name>/g;
		# Services / Service objects
		($service) = $rule =~ /(<services>.*?<\/services>)/;
		(@services) = $service =~ /<Name>(.*?)<\/Name>/g;
		shift @services;
		# Is the rule disabled? 
		($disabled) = $rule =~ /<disabled>(.*?)<\/disabled>/;
		
		# Only gather sources that are in the service policy. Ignore everything else.
		foreach my $src (@srcs) {
			# Prepare for putting into multidimensional hash. (This is for all sources, regardless of it not being an object.)
			# This is because it will be used later to build the rules, whereas the the $inpolicy_ vars are for only including
			# relevant objects to build the object config script.
			if( $src ) { $rule_src = ( $rule_src ) ? "$rule_src,$src" : $src; }
			# Skip is the value is 'Any' or if it's already listed.
			next if ( $src =~ m/Any/ or $inpolicy{'networks'}{$src} == 1 );
			if( $src ) { $inpolicy{'networks'}{$src} = 1; }
		}
		
		# Build destinations that are in policy.
		foreach my $dest (@dests) {
			# Prepare for putting into multidimensional hash. (This is for all dests, regardless of it not being an object.)
			# This is because it will be used later to build the rules, whereas the the $inpolicy_ vars are for only including
			# relevant objects to build the object config script.
			if( $dest ) { $rule_dest = ( $rule_dest ) ? "$rule_dest,$dest" : $dest; }
			# Skip is the value is 'Any' or if it's already listed.
			next if ( $dest =~ m/Any/ or $inpolicy{'networks'}{$dest} );
			if( $dest ) { $inpolicy{'networks'}{$dest} = 1; }
		}

		# Build services that are in policy.
		foreach my $svc (@services) {
			# Prepare for putting into multidimensional hash. (This is for all services, regardless of it not being an object.)
			# This is because it will be used later to build the rules, whereas the the $inpolicy_ vars are for only including
			# relevant objects to build the object config script.
			if( $svc ) { $rule_service = ( $rule_service ) ? "$rule_service,$svc" : $svc; }
			# Skip if the value is 'Any' or if it's already listed.
			next if ( $svc =~ m/Any/ or $inpolicy{'services'}{$svc} == 1 );
			if( $svc ) { $inpolicy{'services'}{$svc} = 1; }
		}

		# Now that all rule information is gathered, place in multidimensional hash.	
		$rules{$rnum}{rnum} = $rnum;
		$rules{$rnum}{name} = $interface."-ACL";
		$rules{$rnum}{interface} = $interface;
		$rules{$rnum}{action} = $asa_action;
		$rules{$rnum}{src} = $rule_src;
		$rules{$rnum}{dest} = $rule_dest;
		$rules{$rnum}{services} = $rule_service;
		$rules{$rnum}{disabled} = $disabled;
		$rules{$rnum}{type} = $type;		# Blank value, must be defined later using the service type.
		$rules{$rnum}{comment} = $comment;
		
		# If the rule was mapped to two interfaces.
		if( $dup_rule == 1 ) {
			print "INFO: Duplicating rule $rnum on $interface interface to ";
			$interface = $inttwo;
			$rnum = $rnum + 1000;
			$rules{$rnum}{rnum} = $rnum;
			$rules{$rnum}{name} = $interface."-ACL";
			$rules{$rnum}{interface} = $interface;
			$rules{$rnum}{action} = $asa_action;
			$rules{$rnum}{src} = $rule_src;
			$rules{$rnum}{dest} = $rule_dest;
			$rules{$rnum}{services} = $rule_service;
			$rules{$rnum}{disabled} = $disabled;
			$rules{$rnum}{type} = $type;		# Blank value, must be defined later using the service type.
			$rules{$rnum}{comment} = $comment;
			print "rule $rnum on $interface interface.\n";
		}
	}
}
close POLICY;

# Also adding the group members to $inpolicy{'networks'} otherwise they wouldn't be created and the created groups would
# reference non-existent objects as members.
open NETWORK, $netfile or die "Couldn't open $netfile for reading, $!.\n";
while(<NETWORK>) {
	my @networks;
	(@networks) = $_ =~ /<network_object>.*?<\/network_object>/g;
	foreach my $network (@networks) {
		# Clear out variables.
		my ($name, $class) = undef;
		
		($name)  = $network =~ /<Name>(.*?)<\/Name>/;
		($class) = $network =~ /<Class_Name>(.*?)<\/Class_Name>/;
		
		# Skip if it's not a group, or if it is already known as in the policy.
		next if ($class !~ m/network_object_group/);
		next if ($inpolicy{'networks'}{$name} != 1);
		
		my (@members) = $network =~ /<reference>\s*<Name>(.*?)<\/Name>/g;
		foreach my $member (@members) {
			$inpolicy{'networks'}{$member} = 1;
		}
	}
}
close NETWORK;

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Build network objects array from network objects xml
# Will be put into a global hash that can be referenced with $networks{'name'}{[key]}.
# Below is the structure of the hash:
# $networks = {
#	'name' => {
#		'class' => $type, # (group, host, network, fqdn, range)
#					 	  # ignore gateway_ckp, cluster_member, 
# 					 	  # dynamic_object, domain, gateway_cluster, 
#						  # sofaware_gateway, security_zone, 
#						  # voip_GK_domain
#		'ip' => $ipaddr,
#		'mask' => $netmask,
#		'fqdn' => $fqdn
#	},
# };
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
open NETWORK, $netfile or die "Couldn't open $netfile for reading, $!.\n";
my (%networks, %netgroup_members, %created_networks);
my $netgroups = undef;

print CONFIG "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
print CONFIG "!!!!!! NETWORK OBJECTS !!!!!!\n";
print CONFIG "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";

while(<NETWORK>) {
	my @networks;
	(@networks) = $_ =~ /<network_object>.*?<\/network_object>/g;
	foreach my $network (@networks) {
		# Clear out variables.
		my ($name, $class, $type, $ip, $mask, $fqdn, $comm) = undef;
		
		($name)  = $network =~ /<Name>(.*?)<\/Name>/;
		($class) = $network =~ /<Class_Name>(.*?)<\/Class_Name>/;
		($type)  = $network =~ /<type><!\[CDATA\[(.*?)\]\]><\/type>/;
		($ip)	 = $network =~ /<ipaddr><!\[CDATA\[(.*?)\]\]><\/ipaddr>/;	# This value doesn't exist in all classes.
		($mask)	 = $network =~ /<netmask><!\[CDATA\[(.*?)\]\]><\/netmask>/;	# This value doesn't exist in all classes.
		($fqdn)  = $network =~ //;
		($comm)  = $network =~ /<comments><!\[CDATA\[(.*?)\]\]><\/comments>/;

		# Skip the object, unless it is used in the service policy.
		next if( $inpolicy{'networks'}{$name} != 1 );
		# If it's not a legitimate class, skip it.
		next if( $class !~ m/[host_plain|network_object_group|network]/ );
		
		# Put values in global multidimensional hash.
		$networks{$name}{name}	= $name;
		$networks{$name}{class} = $class;
		$networks{$name}{type}  = $type;
		$networks{$name}{ip}	= $ip;
		$networks{$name}{mask}  = $mask;
		$networks{$name}{fqdn}  = $fqdn;
		$networks{$name}{comment} = $comm;
				
		if( $class =~ m/network_object_group/ ) {
			# Pull the member references of the group.
			my (@members) = $network =~ /<reference>\s*<Name>(.*?)<\/Name>/g;
			# Create a string of the service-groups to be created later.
			# Ex: group1,group2,group3
			$netgroups = ($netgroups) ? "$netgroups,$name" : $name;
			# Create a string to be used later containing all the member services of the service-group.
			# Ex: service1,service2,service3
			foreach my $member (@members) {
				$netgroup_members{$name} = ($netgroup_members{$name}) ? "$netgroup_members{$name},$member" : $member;
			}
		# If class is host_plain, then treat as a host object.
		} elsif ( $class =~ m/host_plain/ ) {
			print CONFIG "object network $name\n";
			print CONFIG " description $comm\n" if ( $comm );
			print CONFIG " host $ip\n";
			# Log that it was created.
			$created_networks{$name} = 1;
		# If class is network then treat it as a subnet.
		} elsif ( $class =~ m/network/ ) {
			print CONFIG "object network $name\n";
			print CONFIG " description $comm\n" if ( $comm );
			print CONFIG " subnet $ip $mask\n";
			# Log that it was created.
			$created_networks{$name} = 1;
		}
	}
}
close NETWORK;

###############################################################################
# Now that all the objects have been gathered, create the service-groups.
# Split $netgroups into an array (@netgroups) and go through each array value.
###############################################################################
my @netgroups = split( ',', $netgroups );
my $commands_for_later;
print CONFIG "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
print CONFIG "!!! NETWORK OBJECT GROUPS !!!\n";
print CONFIG "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";

foreach my $group (@netgroups) {
	# Split out the member objects into an array.
	my @members = split( ',', $netgroup_members{$group});
	
	# Create the network object-group.
	print CONFIG "object-group network $networks{$group}{name}\n";
	print CONFIG " description $networks{$group}{comment}\n" if( $networks{$group}{comment} );
	
	# Add the members to the group.
	foreach my $member (@members) {
		if( $created_networks{$member} == 1 and $networks{$member}{class} !~ m/network_object_group/ ) {
			print CONFIG " network-object object $member\n";
		} elsif ( $created_networks{$member} == 1 and $networks{$member}{class} =~ m/network_object_group/ ) {
			print CONFIG " group-object $member\n";
		} elsif ( $created_networks{$member} != 1 and $networks{$member}{class} =~ m/network_object_group/ ) {
			$commands_for_later = $commands_for_later."object-group network $networks{$group}{name}\n group-object $member\n";
		} else {
			print "ERROR: CAN NOT ADD NETWORK GROUP MEMBER ($member, type: $networks{$member}{class}) TO NETWORK GROUP ($group) BECAUSE MEMBER DOESN'T EXIST.\n\n";
		}
		# Log that the network group was created.
		$created_networks{$group} = 1;
	}
}

# Also adding the group members to $inpolicy{'services'} otherwise they wouldn't be created and the created groups would
# reference non-existent objects as members.

open SERVICES, $svcfile or die "Couldn't open $svcfile for reading, $!.\n";
while(<SERVICES>) {
	my @services = undef;
	my (@services) = $_ =~ /<service>.*?<\/service>/g;
	foreach my $svc (@services) {
		# Clear out variables.
		my ($name, $class) = undef;
		
		($name)  = $svc =~ /<Name>(.*?)<\/Name>/;
		($class) = $svc =~ /<Class_Name>(.*?)<\/Class_Name>/;
		
		# Skip if it's not a group, or if it is already known as in the policy.
		next if ($class !~ m/service_group/);
		next if ($inpolicy{'services'}{$name} != 1);
		
		my (@members) = $svc =~ /<reference><Name>(.*?)<\/Name><Table>services<\/Table><\/reference>/g;
		foreach my $member (@members) {
			$inpolicy{'services'}{$member} = 1;
		}
	}
}
close SERVICES;

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Build services array from service xml
# Will be put into a global hash that can be referenced with $services{'name'}{[key]}.
# Below is the structure of the hash:
# %services = {
# 	$name => {
# 		'name' => $name,

#		'class' => $class,
# 		'type' => $type,
# 		'port' => $port,
# 		'comment' => $comment
# 	},
# };
#
# Ex: $services{'ssh'}{'type'} would return 'tcp'.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

my (%services, %servgroup_members, %icmptype, %created_services);
my $servgroups;

print CONFIG "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
print CONFIG "!!!!!! SERVICE OBJECTS !!!!!!\n";
print CONFIG "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";

open SERVICES, $svcfile or die "Couldn't open $svcfile for reading, $!.\n";
while(<SERVICES>) {
	my (@services) = $_ =~ /<service>.*?<\/service>/g;

	foreach my $x (@services) {
		my ($name, $type, $comm, $class, $protocol, $port) = undef;
		
		($name) 	= $x =~ /<Name>(.*?)<\/Name>/;
		($type) 	= $x =~ /<type><!\[CDATA\[([a-zA-Z]+)\]\]><\/type>/;
		($type) 		 =~ tr/[A-Z]/[a-z]/;
		($comm) 	= $x =~ /<comments><!\[CDATA\[(.*?)\]\]><\/comments>/;
		($comm)			 =~ s/Oubbound/Outbound/; # Fix typo
		($class)    = $x =~ /<Class_Name>(.*?)<\/Class_Name>/;
		($protocol) = $x =~ /<protocol>(.*?)<\/protocol>/;

		# The port can be presented two ways in the XML. So, we have to make sure to catch either possible syntax while only grabbing the data we want.
		if ($x =~ m/<port><!\[CDATA\[.*?\]\]><\/port>/ ) { ($port) = $x =~ /<port><!\[CDATA\[(.*?)\]\]><\/port>/; }
		elsif ( $x =~ m/<port>.*?<\/port>/ )  { ($port) = $x =~ /<port>(.*?)<\/port>/; }
		
		# Put information into global hashes for referencing outside of this while loop.
		$services{$name}{name} = $name;
		$services{$name}{class} = $class;
		$services{$name}{type} = $type;
		$services{$name}{port} = $port;
		$services{$name}{comment} = $comm;
				
		# Skip the service unless it is used in the policy.
		next unless( $inpolicy{'services'}{$name} );
		# If it isn't a legitimate object type, skip it.
		next if ( $type !~ /(tcp|udp|icmp|icmp6|group)/ );
		# If it is a service_group, store group information in array for printing later.
		# We can't print them now because the group could reference services that haven't been created yet.
		if( $class =~ m/service_group/ ) {
			# Pull the member references of the group.
			my (@members) = $x =~ /<reference><Name>(.*?)<\/Name><Table>services<\/Table><\/reference>/g;			
			# Create a string of the service-groups to be created later.
			# Ex: group1,group2,group3
			$servgroups = ($servgroups) ? "$servgroups,$name" : $name;			
			# Create a string to be used later containing all the member services of the service-group.
			# Ex: service1,service2,service3
			foreach my $y (@members) {
				$servgroup_members{$name} = ($servgroup_members{$name}) ? "$servgroup_members{$name},$y" : $y;
			}
		# If it is a class of icmp_service, use 'icmp' in the syntax, and get the icmp type and use it.
		} elsif ( $class =~ m/icmp_service/ ) {
			# Get the ICMP type.			
			($icmptype) = $x =~ /<icmp_type>(.*?)<\/icmp_type>/;		
			$icmptype{$name} = $icmptype; # For reference later in the script.	
			# Print object config.
			print CONFIG "object service $name\n";
			print CONFIG " description $comm\n" if( $comm );
			print CONFIG " service icmp $icmptype\n";
			# Log the service was created.
			$created_services{$name} = 1;
		# If it is a class of icmpv6_service, use 'icmp6' in the syntax, and get the icmp type and use it.
		} elsif ( $class =~ m/icmpv6_service/ ) {
			# Get the ICMP6 type.
			my ($icmptype) = $x =~ /<icmp_type>(.*?)<\/icmp_type>/;
			$icmptype{$name} = $icmptype; # For reference later in the script.	
			# Print object config.
			print CONFIG "object service $name\n";
			print CONFIG " description $comm\n" if ( $comm );
			print CONFIG " service icmp6 $icmptype\n";	
			# Log the service was created.
			$created_services{$name} = 1;
		# If it a tcp or udp service type, use 'tcp' or 'udp' in the syntax.
		} elsif ( $class =~ m/udp_service/ or $class =~ m/tcp_service/ ) {
			print CONFIG "object service $name\n";
			print CONFIG " description $comm\n" if( $comm );
			# Check to see if it is a port range.
			if( $port =~ m/[0-9]+-[0-9]+/ ) { 
				my ($start) = $port =~ /([0-9]+)-[0-9]+/;
				my ($end)   = $port =~ /[0-9]+-([0-9]+)/;
				print CONFIG " service $type destination range $start $end\n";
			# Otherwise, it must be a single port.
			} else {
				print CONFIG " service $type destination eq $port\n";
			}
			# Log the service was created.
			$created_services{$name} = 1;
		}
	}
}
close SERVICES;

###########################################################################
# Now that all the objects have been gathered, create the service-groups.
# Split $groups into an array and go through each array value.
###########################################################################
print CONFIG "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
print CONFIG "!!! SERVICE GROUP OBJECTS !!!\n";
print CONFIG "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";

my @groups = split( ',', $servgroups );
foreach my $group (@groups) {
	# Split out the member objects into an array.
	my @members = split( ',', $servgroup_members{$group});
	
	my ($is_tcp, $is_udp) = undef;
	# Identify groups with both tcp and udp member services for grouping in next foreach loop.
	foreach my $member (@members) {
		if ( $services{$member}{type} =~ m/tcp/ ) { $is_tcp = 1; }
		if ( $services{$member}{type} =~ m/udp/ ) { $is_udp = 1; }
	}
	
	if( $is_tcp == 1 and $is_udp == 1 ) { $services{$group}{type} = 'tcp-udp'; }
	if( $is_tcp == 1 and $is_udp != 1 ) { $services{$group}{type} = 'tcp'; }
	if( $is_tcp != 1 and $is_udp == 1 ) { $services{$group}{type} = 'udp'; }
	
	# Create object-group
	if( $services{$group}{class} =~ m/service_group/ ) {
		print CONFIG "object-group service $services{$group}{name}\n";
		print CONFIG " description $services{$group}{comment}\n" if( $services{$group}{comm} );
		foreach my $member (@members) {
			next if ( $services{$member}{type} !~ /(tcp|udp|icmp|icmp6|group)/ );
			if( $created_services{$member} == 1 and $services{$member}{class} !~ m/service_group/ ) {
				print CONFIG " service-object object $member\n";
			} elsif ( $created_services{$member} == 1 and $services{$member}{class} =~ m/service_group/ ) {
				print CONFIG " group-object $member\n";
			} elsif ( $created_services{$member} != 1 and $services{$member}{class} =~ m/service_group/ ) {
				$commands_for_later = $commands_for_later."object-group service $services{$group}{name}\n group-object $member\n";
			} else {
				print "CAN NOT ADD SERVICE GROUP MEMBER ($member, class:$services{$member}{class}) TO SERVICE GROUP ($group) BECAUSE MEMBER DOESN'T EXIST.\n\n";
			}
		}
	} elsif ( $services{$group}{type} =~ m/icmp/ ) {
		print CONFIG "object-group icmp-type $group\n";
		print CONFIG " description $services{$group}{comment}\n" if( $services{$group}{comm} );
		foreach my $member (@members) {
			print CONFIG " icmp-object $member\n";    
		}
	}	
	# Log that the service group was created.
	$created_services{$group} = 1;
}

if ( $commands_for_later ) {
	print CONFIG "!\n! CIRCLE BACK TO RETROACTIVELY ADD NESTED GROUPS \n!\n";
	print CONFIG $commands_for_later; 
}

print CONFIG "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
print CONFIG "!!!!!! GROUPS FOR POLICY !!!!!\n";
print CONFIG "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";

# Sort the rules array to be in numerical order, because the order of the policy is important.
my %acls;
foreach my $rnum (sort { $a <=> $b } keys %rules) {
	$acls{$rnum}{name} = $rules{$rnum}{name};
	$acls{$rnum}{action} = $rules{$rnum}{action};

	# Create source group and gather syntax for ACL entry.
	if( $rules{$rnum}{src} =~ m/Any/ ) {
		$acls{$rnum}{src} = "any";
	} else {
		my $count =()= $rules{$rnum}{src} =~ /,/gi;
		my $count = $count + 1;
		
		if( $count == 1 ) {
			my $src = $rules{$rnum}{src};
			if ( $created_networks{$src} == 1 and $networks{$src}{class} !~ m/network_object_group/ ){
				$acls{$rnum}{src} = "object $src";
			} elsif ( $created_networks{$src} == 1 and $networks{$src}{class} =~ m/network_object_group/ ) {
				$acls{$rnum}{src} = "object-group $src";
			}
		} elsif ( $count > 1 ) {
			# Explode the rule's sources into an array.
			my @srcs = split( ',', $rules{$rnum}{src} );
			# Pool all of the services referenced in the CP rule into a object-group to use in ASA config.
			# The name of the created group is defined below:
			my $srcgroup = "cp-$FW-$rnum-src";
			$acls{$rnum}{src} = "object-group $srcgroup";
			# Output object-group config
			print CONFIG "object-group network $srcgroup\n";
			print CONFIG " description net-group destination of cp-$FW-$rnum from CP\n";
			foreach my $src (@srcs) {
				if( $created_networks{$src} == 1 and $networks{$src}{class} !~ m/network_object_group/ ) {
					print CONFIG " network-object object $src\n";
				} elsif ( $created_networks{$src} == 1 and $networks{$src}{class} =~ m/network_object_group/ ) {
					print CONFIG " group-object $src\n";
				} else {
					print "ERROR: COULDN'T ADD SOURCE ($src) AS MEMBER TO $srcgroup BECAUSE THE NETWORK HASN'T BEEN CREATED.\n\n";
				}
			}
		}
	}
	
	# Append destination
	if( $rules{$rnum}{dest} =~ m/Any/ ) {
		$acls{$rnum}{dest} = "any";
	} else {
		my $count =()= $rules{$rnum}{dest} =~ /,/gi;
		my $count = $count + 1;
		
		if( $count == 1 ) {
			my $dest = $rules{$rnum}{dest};
			if( $created_networks{$dest} == 1 and $networks{$dest}{class} !~ m/network_object_group/ ){
				$acls{$rnum}{dest} = "object $dest";
			} elsif ( $created_networks{$dest} == 1 and $networks{$dest}{class} =~ m/network_object_group/) {
				$acls{$rnum}{dest} = "object-group $dest";
			}
		} elsif ( $count > 1 ) {
			# Explode the rule's sources into an array.
			my @dests = split( ',', $rules{$rnum}{dest} );
			# Pool all of the services referenced in the CP rule into a object-group to use in ASA config.
			# The name of the created group is defined below:
			my $destgroup = "cp-$FW-$rnum-dest";
			$acls{$rnum}{dest} = "object-group $destgroup";
			# Output object-group config
			print CONFIG "object-group network $destgroup\n";
			print CONFIG " description net-group sources of cp-$FW-$rnum ACL from CP\n";
			foreach my $dest (@dests) {
				if( $created_networks{$dest} == 1 and $networks{$dest}{class} !~ m/network_object_group/ ) {
					print CONFIG " network-object object $dest\n";		
				} elsif( $created_networks{$dest} == 1 and $networks{$dest}{class} =~ m/network_object_group/ ) {
					print CONFIG " group-object $dest\n";
				} else {
					print "ERROR: COULDN'T ADD DESTINATION ($dest) AS MEMBER TO $destgroup BECAUSE THE NETWORK HASN'T BEEN CREATED.\n\n";
				}
			}
		}
	}
	
	# Append service
	if( $rules{$rnum}{services} =~ m/Any/ ) {
		$acls{$rnum}{svc} = "ip";
		$acls{$rnum}{type} = "ip";
	} else {
		my $count =()= $rules{$rnum}{services} =~ /,/gi;
		my $count = $count + 1;
		
		if( $count == 1 ) {
			my $svc = $rules{$rnum}{services};
			if( $created_services{$svc} == 1 and $services{$svc}{class} !~ m/service_group/ ) {
				$acls{$rnum}{svc} = "object $svc";		
			} elsif ( $created_services{$svc} == 1 and $services{$svc}{class} =~ m/service_group/ ) {
				$acls{$rnum}{svc} = "object-group $svc";
			}
			$acls{$rnum}{type} = ( $services{$svc}{type} =~ m/tcp-udp/ ) ? "ip" : $services{$svc}{type};
		} elsif ( $count > 1 ) {
			# Explode the rule's services into an array.
			my @svcs = split( ',', $rules{$rnum}{services} );
			# Get the service type from the one of the services.
			$rules{$rnum}{type} = ( $services{$svcs[1]}{type} =~ m/tcp-udp/ ) ? "ip" : $services{$svcs[1]}{type};
			$acls{$rnum}{type} = ( $services{$svcs[1]}{type} =~ m/tcp-udp/ ) ? "ip" : $services{$svcs[1]}{type};
			# Pool all of the services referenced in the CP rule into a object-group to use in ASA config.
			# The name of the created group is defined below:
			my $svcgroup = "cp-$FW-$rnum-svc";
			$acls{$rnum}{svc} = "object-group $svcgroup";
			# Output object-group config
			print CONFIG "object-group service $svcgroup\n";
			print CONFIG " description service-group for cp-$FW-$rnum from $FW CP\n";
			foreach my $svc (@svcs) {
				if( $created_services{$svc} == 1 and $services{$svc}{class} !~ m/service_group/ ) {
					print CONFIG " service-object object $svc\n";
				} elsif ( $created_services{$svc} == 1 and $services{$svc}{class} =~ m/service_group/ ) {
					print CONFIG " group-object $svc\n";
				} else {
					print "ERROR: COULDN'T ADD $svc AS MEMBER TO $svcgroup BECAUSE THE SERVICE HASN'T BEEN CREATED.\n\n";

				}
			}
		}
	}
	
	# If rule is disabled, append 'inactive' to ACL.
	$acls{$rnum}{inactive} = ( $rules{$rnum}{disabled} =~ m/true/ ) ? "inactive" : "";
}

print CONFIG "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
print CONFIG "!!!!!!! SERVICE POLICY !!!!!!!\n";
print CONFIG "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";


foreach my $key (sort { $a <=> $b } keys %acls) {
	print CONFIG "access-list $acls{$key}{name} extended $acls{$key}{action} $acls{$key}{svc} $acls{$key}{src} $acls{$key}{dest} $acls{$key}{inactive}\n";
}