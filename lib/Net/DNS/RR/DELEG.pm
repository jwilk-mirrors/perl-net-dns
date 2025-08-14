package Net::DNS::RR::DELEG;

use strict;
use warnings;
our $VERSION = (qw$Id$)[2];

use base qw(Net::DNS::RR::SVCB);


=head1 NAME

Net::DNS::RR::DELEG - DNS DELEG resource record

=cut

use integer;

my %keyname = reverse(
	ip4 => 'key4',
	ip6 => 'key6',
	);


sub _format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	my @rdata;
	for my $key (qw(nsname include)) {
		my $name = $self->$key || next;
		push @rdata, join '=', $key, $name;
	}

	my $priority = $self->priority;
	push @rdata, "priority=$priority" if $priority;

	my $params = $self->{SvcParams} || [];
	my @params = @$params;
	while (@params) {
		my $key = join '', 'key', shift @params;
		my $val = shift @params;
		if ( my $name = $keyname{$key} ) {
			my @val = grep {length} $self->$name;
			my @rhs = grep {length} join ',', @val;
			push @rdata, "\n", join '=', $name, @rhs;
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
			s/\\,/\\044/g;				# disguise escaped comma
			push @value, length() ? split /,/ : ();
		}

		m/^([^=]+)/;					# extract identifier
		$self->$1(@value);
	}
	return;
}


sub _post_parse {			## parser post processing
	my $self = shift;

	my $paramref = $self->{SvcParams} || [];
	unless (@$paramref) {
		return if $self->_empty;
		die 'no parameters specified' unless $self->_targetname;
	}
	return;
}


sub _defaults {				## specify RR attribute default values
	my $self = shift;

	$self->direct('.');
	return;
}


sub direct {
	my ( $self, @servername ) = @_;
	$self->_mode(1) if @servername;
	return $self->_mode ? $self->_targetname(@servername) : undef;
}

sub include {
	my ( $self, @destination ) = @_;
	$self->_mode(0) if @destination;
	return $self->_mode ? undef : $self->_targetname(@destination);
}

sub priority {
	my ( $self, $value ) = @_;
	my $state = $self->{SvcPriority};
	if ( defined $value ) {
		$state = $state ? $state & 1 : 0;
		$self->{SvcPriority} = $state |= ( $value << 8 );
	}
	return $state ? $state >> 8 : $state;
}

sub ip4 {				## ip4=192.0.2.53,...
	my ( $self, @value ) = @_;
	return $self->_SvcParam( 4, _address4(@value) ) unless defined wantarray;
	my $packed = $self->_SvcParam(4);
	my @iplist = unpack 'a4' x ( length($packed) / 4 ), $packed;
	return map { bless( {address => $_}, 'Net::DNS::RR::A' )->address } @iplist;
}

sub ip6 {				## ip6=2001:DB8::53,...
	my ( $self, @value ) = @_;
	return $self->_SvcParam( 6, _address6(@value) ) unless defined wantarray;
	my $packed = $self->_SvcParam(6);
	my @iplist = unpack 'a16' x ( length($packed) / 16 ), $packed;
	return map { bless( {address => $_}, 'Net::DNS::RR::AAAA' )->address } @iplist;
}


sub generic {
	my $self = shift;
	our @ISA;
	my ($super) = @ISA;
	local %Net::DNS::Parameters::classbyval;
	local %Net::DNS::Parameters::typebyval;
	return bless( {%$self}, $super )->string;
}


########################################

sub nsname { return &direct }

sub _mode {
	my ( $self, $value ) = @_;
	my $state = $self->{SvcPriority};
	if ( defined $value ) {
		$state = $state ? $state & 0xff00 : 0;
		$self->{SvcPriority} = $state |= ( $value & 1 );
	}
	return $state ? $state & 1 : $state;
}

sub _targetname {
	my ( $self, @value ) = @_;
	$self->{TargetName} = Net::DNS::DomainName->new(@value) if @value;
	my $target = $self->{TargetName} ? $self->{TargetName}->name : return;
	return $target eq '.' ? undef : $target;
}

sub targetname { __PACKAGE__->_deprecate('TargetName'); return &_targetname }	 # uncoverable pod

sub svcpriority { __PACKAGE__->_deprecate('SvcPriority'); return &priority }	 # uncoverable pod


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
	die "unsupported $method(...)" if @argument;
	return $self->_SvcParam($1);
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

########################################


1;
__END__


=head1 SYNOPSIS

	use Net::DNS;
	$rr = Net::DNS::RR->new('zone DELEG nsname=nameserver IPv4=192.0.2.1');
	$rr = Net::DNS::RR->new('zone DELEG IPv6=2001:db8::53');
	$rr = Net::DNS::RR->new('zone DELEG include=targetname');

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


=head2 nsname

=head2 direct

	example. DELEG nsname=nameserver.example.
	$nameserver = $rr->nsname;

Specifies the domain name of the nameserver and sets DIRECT mode.

Returns the nameserver domain name or the undefined value if not specified.


=head2 include

	example. DELEG include=devolved.example.
	$destination = $rr->include;

Specifies the location of a devolved nameserver configuration and sets INCLUDE mode.

Returns the INCLUDE destination domain name or the undefined value if not specified.


=head2 priority

	example. DELEG	nsname=... priority=123
	example. DELEG	include=... priority=123
	$priority = $rr->priority;

Gets or sets the priority value for the DELEG record.


=head2 ip4

	example. DELEG nsname=... IP4=192.0.2.1
	@ip = $rr->IP4;

Sets or gets a list of IP addresses.

=head2 ip6

	example. DELEG nsname=... IP6=2001:db8::53
	@ip = $rr->IP6;

Sets or gets a list of IP addresses.


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
