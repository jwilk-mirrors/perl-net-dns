#!/usr/bin/perl
# $Id$	-*-perl-*-
#

use strict;
use warnings;
use Net::DNS;

use Test::More;
use TestToolkit;

exit( plan skip_all => 'unresolved AUTOLOAD regression	[perl #120694]' )
		unless ( $] > 5.018001 )
		or ( $] < 5.018 );

plan tests => 37;


my $type = 'DELEG';

my $typecode = unpack 'xn', Net::DNS::RR->new( type => $type )->encode;
ok( $typecode, "$type RR type code = $typecode" );


for my $rr ( Net::DNS::RR->new( my $record = 'example. DELEG' ) ) {
	ok( $rr, "new DELEG RR:	$record" );
	is( $rr->DIRECT,  undef, 'DIRECT undefined' );
	is( $rr->INCLUDE, undef, 'INCLUDE undefined' );
	is( $rr->rdata,	  '',	 'empty rdata' );
	ok( $rr->string,  'presentation format string' );
	ok( $rr->generic, 'RFC3597 generic format' );
}


for my $rr ( Net::DNS::RR->new( my $record = 'example. DELEG DIRECT="nameserver.example"' ) ) {
	ok( $rr, "new DELEG RR:	$record" );
	is( $rr->DIRECT,	'nameserver.example', 'DIRECT defined' );
	is( $rr->INCLUDE,	undef,		      'INCLUDE undefined' );
	is( $rr->priority,	0,		      'default priority zero' );
	is( $rr->priority(123), 123,		      'set arbitrary priority' );
	ok( $rr->string,  'presentation format string' );
	ok( $rr->generic, 'RFC3597 generic format' );
}


for my $rr ( Net::DNS::RR->new( my $record = 'example. DELEG ip4=192.0.2.1 alpn=dot' ) ) {
	ok( $rr, "new DELEG RR:	$record" );
	is( $rr->DIRECT,  undef, 'DIRECT  undefined' );
	is( $rr->INCLUDE, undef, 'INCLUDE undefined' );
	ok( $rr->string,  'presentation format string' );
	ok( $rr->generic, 'RFC3597 generic format' );
}


for my $rr ( Net::DNS::RR->new( my $record = 'example. DELEG INCLUDE="devolved.example"' ) ) {
	ok( $rr, "new DELEG RR:	$record" );
	is( $rr->INCLUDE,	'devolved.example', 'INCLUDE defined' );
	is( $rr->DIRECT,	undef,		    'DIRECT undefined' );
	is( $rr->priority,	0,		    'default priority zero' );
	is( $rr->priority(123), 123,		    'set arbitrary priority' );
	ok( $rr->string,  'presentation format string' );
	ok( $rr->generic, 'RFC3597 generic format' );
}


for my $rr ( Net::DNS::RR->new( my $record = 'example. DELEG DIRECT=example ip4=192.0.2.1,192.0.2.2' ) ) {
	ok( $rr,		 "new DELEG RR:	$record" );
	ok( defined $rr->key4(), 'correct SvcParameter key defined' );
	my @list = eval { $rr->ip4 };
	ok( scalar @list, '$rr->ip4 returns address list' );
}

for my $rr ( Net::DNS::RR->new( my $record = 'example. DELEG DIRECT=example ip6=2001:db8::1' ) ) {
	ok( $rr,		 "new DELEG RR:	$record" );
	ok( defined $rr->key6(), 'correct SvcParameter key defined' );
	my @list = eval { $rr->ip6 };
	ok( scalar @list, '$rr->ip6 returns address list' );
}

exception( 'no parameter specified', sub { Net::DNS::RR->new('example. DELEG DIRECT=.') } );
exception( 'unrecognised parameter', sub { Net::DNS::RR->new('example. DELEG bogus') } );
exception( 'unsupported parameter',  sub { Net::DNS::RR->new('example. DELEG')->key1('dot') } );
exception( 'deprecated parameter',   sub { Net::DNS::RR->new('example. DELEG')->SvcPriority } );
exception( 'deprecated parameter',   sub { Net::DNS::RR->new('example. DELEG')->TargetName } );


exit;

