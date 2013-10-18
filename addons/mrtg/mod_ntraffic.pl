#!/usr/bin/perl

#
# Interface for apache mod_traffic and mrtg.
#
# Copyright 2005 by Massimo Cetra <mcetra@gmail.com>.  All rights reserved.
#

use strict;

my $dirfiles="/var/spool/apache/mod_ntraffic/";

#*******************************************
#*******************************************  DON'T EDIT BELOW HERE
#*******************************************

my $host=@ARGV[0];

if ( $host ne "" ) {
    ParseVhostData($host);
} else {
    print "0\n0\nNOT FOUND\nNOT FOUND\n";
}

#********************************************

sub ParseVhostData() {
    my ($vhost)=@_;
    my $line;

    my $file="$dirfiles".$vhost.".data";

    if ( ! -f $file ) {
	print "0\n0\nNOT FOUND\nNOT FOUND\n";
	return;
    }

    open (FILE,$file);
    $line=<FILE>;
    close(FILE);

    my ($sent,$rec,$hits)=split(" ",$line);


    print "$sent\n";
    print "$rec\n";
    # Parse though getuptime and get data
    my $getuptime = `/usr/bin/uptime`;
    my ($getuptime,$foo)=split(',',$getuptime);
    chomp($getuptime);
    print "$getuptime\n";
    print "$vhost\n";

}

1;
