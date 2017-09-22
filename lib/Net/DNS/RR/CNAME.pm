package Net::DNS::RR::CNAME;

#
# $Id$
#
our $VERSION = (qw$LastChangedRevision$)[1];


use strict;
use warnings;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::CNAME - DNS CNAME resource record

=cut


use integer;

use Net::DNS::DomainName;


sub _decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;

	$self->{cname} = decode Net::DNS::DomainName1035(@_);
}


sub _encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	my $cname = $self->{cname};
	$cname->encode(@_);
}


sub _format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	my $cname = $self->{cname};
	$cname->string;
}


sub _parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->cname(shift);
}


sub cname {
	my $self = shift;

	$self->{cname} = new Net::DNS::DomainName1035(shift) if scalar @_;
	$self->{cname}->name if $self->{cname};
}


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name CNAME cname');

    $rr = new Net::DNS::RR(
	name  => 'alias.example.com',
	type  => 'CNAME',
	cname => 'example.com',
	);

=head1 DESCRIPTION

Class for DNS Canonical Name (CNAME) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 cname

    $cname = $rr->cname;
    $rr->cname( $cname );

A domain name which specifies the canonical or primary name for
the owner.  The owner name is an alias.


=head1 COPYRIGHT

Copyright (c)1997 Michael Fuhr. 

Portions Copyright (c)2002-2003 Chris Reinhardt.

All rights reserved.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 LICENSE

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted, provided
that the above copyright notice appear in all copies and that both that
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

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1035 Section 3.3.1

=cut
