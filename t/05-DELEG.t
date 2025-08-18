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

plan tests => 46;


my $type = 'DELEG';

my $typecode = unpack 'xn', Net::DNS::RR->new( type => $type )->encode;
ok( $typecode, "$type RR type code = $typecode" );


for my $rr ( Net::DNS::RR->new( my $record = 'example. DELEG' ) ) {
	ok( $rr, "new DELEG RR:	$record" );
	is( $rr->IP4,	  undef, 'IP4 undefined' );
	is( $rr->IP6,	  undef, 'IP6 undefined' );
	is( $rr->NSNAME,  undef, 'NSNAME undefined' );
	is( $rr->INCLUDE, undef, 'INCLUDE undefined' );
	is( $rr->rdata,	  '',	 'empty rdata' );
	ok( $rr->string,  'presentation format string' );
	ok( $rr->generic, 'RFC3597 generic format' );
}


for my $rr ( Net::DNS::RR->new( my $record = 'example. DELEG IP4=192.0.2.1,192.0.2.2' ) ) {
	ok( $rr,		 "new DELEG RR:	$record" );
	ok( defined $rr->key1(), 'correct parameter key defined' );
	my @list = eval { $rr->IP4 };
	ok( scalar @list, '$rr->IP4 returns address list' );
	is( $rr->INCLUDE, undef, 'INCLUDE undefined' );
}

for my $rr ( Net::DNS::RR->new( my $record = 'example. DELEG IP6=2001:db8::1' ) ) {
	ok( $rr,		 "new DELEG RR:	$record" );
	ok( defined $rr->key2(), 'correct parameter key defined' );
	my @list = eval { $rr->IP6 };
	ok( scalar @list, '$rr->IP6 returns address list' );
	is( $rr->INCLUDE, undef, 'INCLUDE undefined' );
}

for my $rr ( Net::DNS::RR->new( my $record = 'example. DELEG NSNAME=nameserver.example' ) ) {
	ok( $rr,		 "new DELEG RR:	$record" );
	ok( defined $rr->key3(), 'correct parameter key defined' );
	is( $rr->NSNAME,  'nameserver.example.', '$rr->NSNAME returns domain name' );
	is( $rr->INCLUDE, undef,		 'INCLUDE undefined' );
}

for my $rr ( Net::DNS::RR->new( my $record = 'example. DELEG INCLUDE="devolved.example"' ) ) {
	ok( $rr,		 "new DELEG RR:	$record" );
	ok( defined $rr->key4(), 'correct parameter key defined' );
	is( $rr->INCLUDE, 'devolved.example.', '$rr->INCLUDE returns domain name' );
	is( $rr->NSNAME,  undef,	       'NSNAME undefined' );
	is( $rr->IP4,	  undef,	       'IP4 undefined' );
	is( $rr->IP6,	  undef,	       'IP6 undefined' );
}


for my $rr ( Net::DNS::RR->new( my $record = 'example. 0 IN DELEG' ) ) {
	ok( $rr, "new DELEG RR:	$record" );
	is( $rr->rdata, '', 'empty rdata' );
	ok( $rr->IP4('192.0.2.1'),		'IP4 access method' );
	ok( $rr->IP6('2001:db8::53'),		'IP6 access method' );
	ok( $rr->NSNAME('nameserver.example.'), 'NSNAME access method' );
	ok( $rr->INCLUDE('devolved.example.'),	'INCLUDE access method' );
	ok( $rr->rdata,				'non-empty rdata' );
	ok( $rr->encode,			'wire-format octet string' );
	ok( !$rr->_parameter( 4, undef ),	'delete INCLUDE parameter' );
	ok( $rr->_parameter( 65500, '!' ),	'unexpected parameter' );
	ok( $rr->string,			'presentation format string' );
	ok( $rr->generic,			'RFC3597 generic format' );
	my $encoded = $rr->encode;
	my $decoded = ref($rr)->decode( \$encoded );
	is( $decoded->generic, $rr->generic, 'encode/decode transparent' );
	my $rdata = pack 'n2a*', 65500, 5, 'xxxx';
	local $rr->{rdlength} = length $rdata;
	exception( 'rdata corruption', sub { $rr->_decode_rdata( \$rdata, 0 ) } );
}


exception( 'duplicated parameter',   sub { Net::DNS::RR->new('example. DELEG INCLUDE=x INCLUDE=y') } );
exception( 'additional arguments',   sub { Net::DNS::RR->new('example. DELEG INCLUDE=x,y') } );
exception( 'incompatible parameter', sub { Net::DNS::RR->new('example. DELEG INCLUDE=x NSNAME=y') } );
exception( 'unsupported parameter',  sub { Net::DNS::RR->new('example. DELEG')->key65500('') } );
exception( 'unrecognised parameter', sub { Net::DNS::RR->new('example. DELEG bogus') } );

exit;

