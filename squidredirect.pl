#!/usr/bin/perl

use strict;
use File::Temp qw/ tempfile tempdir /;
use URI::URL;
use Net::DNS;

my $res = Net::DNS::Resolver->new;
my $fh;
my $filename;
my $url;
my $rest;
my $url2;
my $host;
my $bl = '.multi.surbl.org';
my $query ;
my $answer;

$res->nameservers('127.0.0.1');

($fh, $filename) = tempfile("/tmp/squidredir_XXXXXXXXXXX");
$| = 1;

while (<>){
	($url, $rest) = split(/ /, $_);
	$url2 = new URI::URL $url;
	$host = $url2->host;
	print $fh "$host\n";
	
	$query = $res->search($host . $bl);
	
	$answer = "OK";
	if ($query) {
		foreach my $rr ($query->answer) {
			next unless $rr->type eq "A";
			next if $rr->address eq '10.1.1.25';
			$answer = 'OK status=301 url="https://whatever"';
		}
	}
	print $fh "$answer\n";

	print "$answer\n";
}

close $fh;
