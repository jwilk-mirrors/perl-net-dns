#!/usr/bin/perl
# $Id$	-*-perl-*-
#

use strict;
use warnings;
use Net::DNS;
use Net::DNS::ZoneFile;

use Test::More;
use TestToolkit;

exit( plan skip_all => 'unresolved AUTOLOAD regression	[perl #120694]' )
		unless ( $] > 5.018001 )
		or ( $] < 5.018 );

plan tests => 17;


my $type = 'DELEG';
my $code = $Net::DNS::Parameters::typebyname{$type};

my $typecode = unpack 'xn', Net::DNS::RR->new( type => $type )->encode;
is( $typecode, $code, "$type RR type code = $code" );


for my $rr ( Net::DNS::RR->new('example. IN DELEG') ) {
	is( $rr->targetname, undef, 'empty DELEG with undefined targetname' );
	ok( $rr->string,  'presentation format string' );
	ok( $rr->generic, 'RFC3597 generic format' );
}


for my $rr ( Net::DNS::RR->new(<<'END') ) {
example.	DELEG	(
	DIRECT=nsdname
	IPv4=192.0.2.1
	IPv6=2001:db8::53
	port=53
	priority=123 )
END
	ok( $rr->targetname, 'DELEG with specified servername' );
	ok( $rr->string,     'presentation format string' );
}


for my $rr ( Net::DNS::RR->new('example. IN DELEG IPv6=2001:db8::53') ) {
	is( $rr->targetname, undef, 'DELEG with unspecified targetname' );
	ok( $rr->string, 'presentation format string' );
}


for my $rr ( Net::DNS::RR->new('. DELEG INCLUDE="target"') ) {
	is( $rr->targetname, 'target', 'INCLUDE key specifies targetname' );
	ok( $rr->string,  'presentation format string' );
	ok( $rr->generic, 'RFC3597 generic format' );
	exception( 'priority parameter disallowed',  sub { $rr->_parse_rdata('priority=123') } );
	exception( 'generic keyNN=value disallowed', sub { $rr->_parse_rdata(qw(key123= "x")) } );
	exception( 'generic boolean key disallowed', sub { $rr->_parse_rdata('key123') } );
	exception( 'unknown boolean key disallowed', sub { $rr->_parse_rdata('bogus') } );
}

exception( 'incomplete INCLUDE parameter', sub { Net::DNS::RR->new('example. DELEG INCLUDE') } );
exception( 'incomplete DIRECT parameter',  sub { Net::DNS::RR->new('example. DELEG DIRECT') } );

exit;

