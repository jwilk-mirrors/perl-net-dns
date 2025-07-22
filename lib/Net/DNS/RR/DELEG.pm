package Net::DNS::RR::DELEG;

use strict;
use warnings;
our $VERSION = (qw$Id$)[2];

use base qw(Net::DNS::RR::SVCB);


=head1 NAME

Net::DNS::RR::DELEG - DNS DELEG resource record

=cut

use integer;
use Carp;

my %keyname = reverse(
	IPv4 => 'key4',
	IPv6 => 'key6',
	);


sub _format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	my $priority = $self->{SvcPriority};
	my @target   = grep { $_ ne '.' } $self->{TargetName}->string;
	my $mode     = $priority ? 'DIRECT' : 'INCLUDE';
	my @rdata    = join '=', $mode, @target;
	push @rdata, "priority=$priority" if $priority > 1;

	my $params = $self->{SvcParams} || [];
	my @params = @$params;
	while (@params) {
		my $key = join '', 'key', shift @params;
		my $val = shift @params;
		if ( my $name = $keyname{$key} ) {
			push @rdata, join '=', $name, $self->$name;
		} else {
			my @hex = unpack 'H*', $val;
			$self->_annotation(qq(unexpected $key="@hex"));
		}
	}

	return @rdata;
}


sub _parse_rdata {			## populate RR from rdata in argument list
	my ( $self, @argument ) = @_;

	while ( my $parameter = shift @argument ) {
		for ($parameter) {
			my @value;
			if (/^[^=]+=(.*)$/) {
				local $_ = length($1) ? $1 : shift @argument;
				s/^"([^"]*)"$/$1/;		# strip enclosing quotes
				s/\\,/\\044/g;			# disguise escaped comma
				push @value, split /,/;
			}

			s/[-]/_/g;				# extract identifier
			m/^([^=]+)/;
			$self->$1(@value);
		}
	}
	return;
}


sub _post_parse {			## parser post processing
	my $self = shift;

	my $paramref = $self->{SvcParams} || [];
	unless (@$paramref) {
		return if $self->_empty;
		die('target name not specified') unless $self->targetname;
	}
	return;
}


sub _defaults {				## specify RR attribute default values
	my $self = shift;

	$self->DIRECT;
	return;
}


sub direct {
	my ( $self, @servername ) = @_;				# uncoverable pod
	$self->targetname( @servername, '.' );
	return $self->{SvcPriority} = 1;
}

sub include {
	my ( $self, $target ) = @_;				# uncoverable pod
	$self->targetname($target);
	return $self->{SvcPriority} = 0;
}

sub priority {
	my ( $self, @value ) = @_;				# uncoverable pod
	return $self->{SvcPriority}	     unless @value;
	croak 'priority invalid for INCLUDE' unless $self->{SvcPriority};
	return $self->{SvcPriority} = shift @value;
}

sub targetname {
	my ( $self, @value ) = @_;
	$self->{TargetName} = Net::DNS::DomainName->new(@value) if @value;
	my $target = $self->{TargetName} ? $self->{TargetName}->name : return;
	return $target eq '.' ? undef : $target;
}

sub ip4 {				## ip4=192.0.2.53,...
	my ( $self, @value ) = @_;				# uncoverable pod
	my $ip = $self->SUPER::ipv4hint(@value);
	return $ip if @value;
	my @ip = unpack 'a4' x ( length($ip) / 4 ), $ip;
	return join ',', map { bless( {address => $_}, 'Net::DNS::RR::A' )->address } @ip;
}

sub ip6 {				## ip6=2001:DB8::53,...
	my ( $self, @value ) = @_;				# uncoverable pod
	my $ip = $self->SUPER::ipv6hint(@value);
	return $ip if @value;
	my @ip = unpack 'a16' x ( length($ip) / 16 ), $ip;
	return join ',', map { bless( {address => $_}, 'Net::DNS::RR::AAAA' )->address_short } @ip;
}

sub ipv4 { return &ip4 }					# uncoverable pod
sub ipv6 { return &ip6 }					# uncoverable pod

sub generic {
	my $self  = shift;
	my @ttl	  = grep {defined} $self->{ttl};
	my @class = map	 { $_ ? "CLASS$_" : () } $self->{class};
	my @core  = ( $self->{owner}->string, @ttl, @class, "TYPE$self->{type}" );
	my @rdata = $self->_empty ? () : $self->SUPER::_format_rdata;
	return join "\n\t", Net::DNS::RR::_wrap( "@core (", @rdata, ')' );
}


1;
__END__


=head1 SYNOPSIS

	use Net::DNS;
	$rr = Net::DNS::RR->new('zone DELEG DIRECT=nameserver IPv4=192.0.2.1');
	$rr = Net::DNS::RR->new('zone DELEG DIRECT IPv6=2001:db8::53');
	$rr = Net::DNS::RR->new('zone DELEG INCLUDE=targetname');

=head1 DESCRIPTION


The DNS DELEG resource record set, wherever it appears, advertises the
authoritative nameservers and transport parameters to be used to resolve
queries for data at the owner name or any subordinate thereof.

The DELEG RRset is authoritative data within the delegating zone
and must not appear at the apex of the subordinate zone.

The DELEG class is derived from, and inherits properties of,
the Net::DNS::RR::SVCB class.


=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 DIRECT

	example. DELEG DIRECT=nameserver
	example. DELEG DIRECT=nameserver IPv6=2001:db8::53
	example. DELEG DIRECT IPv4=192.0.2.1 IPv6=2001:db8::53
	$nameserver = $rr->targetname;

Specifies the nameserver domain name, which may be absent,
and sets DIRECT mode (non-zero SvcPriority).


=head2 INCLUDE

	example. DELEG INCLUDE=targetname
	$targetname = $rr->targetname;

Specifies the location of an external nameserver configuration
and sets INCLUDE mode (zero SvcPriority).


=head2 targetname

	$target = $rr->targetname;

Returns the target domain name or the undefined value if not specified.


=head2 IPv4

	example. DELEG DIRECT IPv4=192.0.2.1
	@ip = $rr->IPv4;

Sets or gets the list of IP addresses.

=head2 IPv6

	example. DELEG DIRECT IPv6=2001:db8::53
	@ip = $rr->IPv6;

Sets or gets the list of IP addresses.


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
L<Net::DNS::RR::SVCB>

draft-ietf-deleg

L<RFC9460|https://iana.org/go/rfc9460>

L<Service Parameter Keys|https://iana.org/assignments/dns-svcb>

=cut
