package Net::DNS::RR::DELEG;

use strict;
use warnings;
our $VERSION = (qw$Id$)[2];

use base qw(Net::DNS::RR);


=head1 NAME

Net::DNS::RR::DELEG - DNS DELEG resource record

=cut

use integer;

use Net::DNS::RR::A;
use Net::DNS::RR::AAAA;
use Net::DNS::DomainName;

my %keyname = (
	key1 => 'server-ip4',
	key2 => 'server-ip6',
	key3 => 'server-name',
	key4 => 'include-name',
	);


sub _decode_rdata {			## decode rdata from wire-format octet string
	my ( $self, $data, $offset ) = @_;

	my $limit = $self->{rdlength};
	my $rdata = $self->{rdata} = substr $$data, $offset, $limit;
	my $index = 0;

	my $params = $self->{parameters} = [];
	while ( ( my $start = $index + 4 ) <= $limit ) {
		my ( $key, $size ) = unpack( "\@$index n2", $rdata );
		last if ( $index = $start + $size ) > $limit;
		push @$params, ( $key, substr $rdata, $start, $size );
	}
	die $self->type . ': corrupt RDATA' unless $index == $limit;
	return;
}


sub _encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	my @packed;
	my ($paramref) = grep {defined} $self->{parameters}, [];
	my @parameters = @$paramref;
	while (@parameters) {
		my $key = shift @parameters;
		my $val = shift @parameters;
		push @packed, pack( 'n2a*', $key, length($val), $val );
	}
	return join '', @packed;
}


sub _format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	my @rdata;
	my ($paramref) = grep {defined} $self->{parameters}, [];
	my @parameters = @$paramref;
	while (@parameters) {
		my $key = join '', 'key', shift @parameters;
		my $val = shift @parameters;
		if ( my $name = $keyname{$key} ) {
			my @val = grep {length} $self->$name;
			my @rhs = grep {length} join ',', @val;
			push @rdata, join '=', $name, @rhs;
		} else {
			my @hex = unpack 'H*', $val;
			$self->_annotation(qq(unexpected $key="@hex"));
		}
	}

	return @rdata;
}


sub _parse_rdata {			## populate RR from rdata in argument list
	my ( $self, @argument ) = @_;

	while ( local $_ = shift @argument ) {
		my @value;
		m/^[^=]+=?(.*)$/;
		for ( my $rhs = /=$/ ? shift @argument : $1 ) {
			s/^"(.*)"$/$1/;				# strip enclosing quotes
			push @value, length() ? split /,/ : ();
		}

		m/^([^=]+)/;					# extract identifier
		$self->$1(@value);
	}
	return;
}


sub _post_parse {			## parser post processing
	my $self = shift;

	my ($paramref) = grep {defined} $self->{parameters}, [];
	my %paramhash  = @$paramref;
	if ( delete $paramhash{4} ) {
		die( $self->type . qq[: parameter conflicts with include-name] ) if scalar keys %paramhash;
	}
	return;
}


sub server_ip4 {			## server-ip4=192.0.2.53
	my ( $self, @value ) = @_;
	return $self->_parameter( 1, _address4(@value) ) if @value;
	my $packed = $self->_parameter(1) || return;
	my @iplist = unpack 'a4' x ( length($packed) / 4 ), $packed;
	return map { bless( {address => $_}, 'Net::DNS::RR::A' )->address } @iplist;
}

sub server_ip6 {			## server-ip6=2001:DB8::53
	my ( $self, @value ) = @_;
	return $self->_parameter( 2, _address6(@value) ) if @value;
	my $packed = $self->_parameter(2) || return;
	my @iplist = unpack 'a16' x ( length($packed) / 16 ), $packed;
	return map { bless( {address => $_}, 'Net::DNS::RR::AAAA' )->address } @iplist;
}

sub server_name {			## server-name=nameserver.example
	my ( $self, @value ) = @_;
	return $self->_parameter( 3, _domain(@value) ) if @value;
	my $packed = $self->_parameter(3) || return;
	return Net::DNS::DomainName->decode( \$packed )->fqdn;
}

sub include_name {			## include-name=devolved.example
	my ( $self, @value ) = @_;
	return $self->_parameter( 4, _domain(@value) ) if @value;
	my $packed = $self->_parameter(4) || return;
	return Net::DNS::DomainName->decode( \$packed )->fqdn;
}


########################################

sub AUTOLOAD {				## Dynamic constructor/accessor methods
	my ( $self, @argument ) = @_;

	our $AUTOLOAD;
	my ($method)  = reverse split /::/, $AUTOLOAD;
	my $canonical = lc($method);
	$canonical =~ s/-/_/g;
	if ( $self->can($canonical) ) {
		no strict 'refs';	## no critic ProhibitNoStrict
		*{$AUTOLOAD} = sub { shift->$canonical(@_) };
		return $self->$canonical(@argument);
	}

	my $super = "SUPER::$method";
	return $self->$super(@argument) unless $method =~ /^key[0]*(\d+)$/i;
	die( $self->type . qq[: unsupported $method(...)] ) if @argument;
	return $self->_parameter($1);
}


sub _parameter {
	my ( $self, $key, @argument ) = @_;

	my ($paramref) = grep {defined} $self->{parameters}, [];
	my %parameter  = @$paramref;

	if ( scalar @argument ) {
		my $arg = shift @argument;			# key($value);
		delete $parameter{$key} unless defined $arg;
		die( $self->type . qq[: duplicate parameter "key$key"] ) if defined $parameter{$key};
		die( $self->type . qq[: unexpected "key$key" value] )	 if scalar @argument;
		delete $self->{rdata};
		$parameter{$key} = $arg if defined $arg;
		$self->{parameters} = [map { ( $_, $parameter{$_} ) } sort { $a <=> $b } keys %parameter];
	}

	return $parameter{$key};
}


sub _concatenate {			## concatenate octet string(s)
	my @arg = @_;
	return scalar(@arg) > 1 ? join( '', @arg ) : @arg;
}

sub _address4 {
	my @arg = @_;
	return _concatenate( map { Net::DNS::RR::A::address( {}, $_ ) } @arg );
}

sub _address6 {
	my @arg = @_;
	return _concatenate( map { Net::DNS::RR::AAAA::address( {}, $_ ) } @arg );
}

sub _domain {
	my @arg = @_;
	return map { Net::DNS::DomainName->new($_)->encode() } @arg;
}


# uncoverable pod
sub ip4 { return &server_ip4 }

# uncoverable pod
sub ip6 { return &server_ip6 }

# uncoverable pod
sub nsname { return &server_name }

# uncoverable pod
sub include { return &include_name }


########################################


1;
__END__


=head1 SYNOPSIS

	use Net::DNS;
	$rr = Net::DNS::RR->new('zone DELEG server-name=nameserver server-ip4=192.0.2.1');
	$rr = Net::DNS::RR->new('zone DELEG server-ip6=2001:db8::53');
	$rr = Net::DNS::RR->new('zone DELEG include-name=targetname');

=head1 DESCRIPTION


The DNS DELEG resource record set, wherever it appears, advertises the
authoritative nameservers and transport parameters to be used to resolve
queries for data at the owner name or any subordinate thereof.

The DELEG RRset is authoritative data within the delegating zone
and must not appear at the apex of the subordinate zone.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 server_ip4

=head2 server-ip4

	example. DELEG server-name=... server-ip4=192.0.2.1
	@ip = $rr->server_ip4;

Sets or gets a list of IP addresses.


=head2 server_ip6

=head2 server-ip6

	example. DELEG server-name=... server-ip6=2001:db8::53
	@ip = $rr->server_ip6;

Sets or gets a list of IP addresses.


=head2 server_name

=head2 server-name

	example. DELEG server-name=nameserver.example.
	$nameserver = $rr->server_name;

Specifies the domain name of the nameserver.

Returns the nameserver domain name or the undefined value if not specified.


=head2 include_name

=head2 include-name

	example. DELEG include-name=devolved.example.
	$destination = $rr->include_name;

Specifies the location of a devolved nameserver configuration.

Returns the destination domain name or the undefined value if not specified.


=head1 COPYRIGHT

Copyright (c)2025 Dick Franks. 

All rights reserved.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 LICENSE

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted, provided
that the original copyright notices appear in all copies and that both
copyright notice and this permission notice appear in supporting
documentation, and that the name of the author not be used in advertising
or publicity pertaining to distribution of the software without specific
prior written permission.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.


=head1 SEE ALSO

L<perl> L<Net::DNS> L<Net::DNS::RR>
draft-ietf-deleg-02

=cut
