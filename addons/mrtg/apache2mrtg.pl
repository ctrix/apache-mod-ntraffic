#!/usr/bin/perl

#
# Parses apache config dir looking for virtual hosts.
# Then creates (on STDOUT) a simple configuration template
# for MRTG
#
# Copyright 2005 by Massimo Cetra <mcetra@gmail.com>.  All rights reserved.
#

my $CONFDIR="/etc/apache";	# Directory where httpd.conf is located
my $SCRIPTDIR="/usr/local/bin"; # no trailing slash
my $SCRIPTNAME="mod_ntraffic.pl";

#*******************************************
#*******************************************  DON'T EDIT BELOW HERE
#*******************************************
use strict;
use Cwd;


my %seen=();
my $topdir = $CONFDIR;
my $currdir = cwd();

chdir $topdir;
&dodir($topdir,0);

sub dodir {
    my ($dir,$nlink) = @_;
    my ($dev,$ino,$mode,$subcount);
    my( $filename );
    my @filenames;

    
    #print "****************************************\n";
    #print "Checking in $dir\n";
    #print "****************************************\n";

    # At the top level, we need to find nlink ourselves.
    ($dev,$ino,$mode,$nlink) = stat('.') unless $nlink;

    # Get the list of files in the current directory.

    opendir(DIR,'.') || die "Can't open $dir";
	@filenames = readdir(DIR);
    closedir(DIR);

    if ($nlink == 2) {        # This dir has no subdirectories.

        for (@filenames) {
            next if $_ eq '.';
            next if $_ eq '..';
            # print "Thatlevel: $dir/$_\n";
            my $filename = "$_";
            if ( -f $filename && -T _ ) { 
		$filename = "$dir/$_";
		ParseFile($filename);
	    }

        } 
    } else {                    # This dir has subdirectories.
        $subcount = $nlink - 2;
        for (@filenames) {
            next if $_ eq '.';
            next if $_ eq '..';
            my $name = "$dir/$_";
            my $filename = "$name";
            if ( -f $filename && -T _ ) { 
		ParseFile($filename);
	    }

            next if $subcount == 0;    # Seen all the subdirs?
            # Get link count and check for directoriness.
            ($dev,$ino,$mode,$nlink) = lstat($_);
            next unless -d _;
            # It really is a directory, so do it recursively.
            chdir $_ || die "Can't cd to $name";
            &dodir($name,$nlink);
            chdir '..';
            --$subcount;
        }
    }
}

#-------------------------------------------------------
sub ParseFile() {
    my ($file)=@_;
    my $name;

    open (FILE,$file);
    while (<FILE>) {
	# Skip commented blocks
	next if m!\#.*</?virtualhost!i;
	if (m!<virtualhost\s!i .. m!</virtualhost>!i) {
		$name = $1 if m!ServerName\s+(\S+)!;
	}
	if (m!</virtualhost>!i) {
		MakeTarget($name);
	}
}


    close(FILE);

}

#-------------------------------------------------------
sub MakeTarget() {
    my ($host)=@_;

    if ($seen{$host}) {
	#print STDERR "DUPLICATE entry \"$host\"\n";
	return;
    }

    $seen{$host} = 1;

    print <<EOT;
Title[$host]: $host Data Traffic
Target[$host]: `${SCRIPTDIR}/${SCRIPTNAME} $host`
MaxBytes[$host]: 1250000
PageTop[$host]: <h2><a href="http://$host/">$host</a> Data Traffic</h2>

EOT

}

1;
