# $Id$	-*-perl-*-
#

use strict;


BEGIN {
	use Test::More;

	my @prerequisite = qw(
			Net::DNS::SEC
			Net::DNS::SEC::ECDSA
			);

	foreach my $package (@prerequisite) {
		plan skip_all => "$package not installed"
				unless eval "require $package";
	}

	plan tests => 7;

	use_ok('Net::DNS::SEC');
}


my $ksk = new Net::DNS::RR <<'END';
ECDSAP256SHA256.example.	IN	DNSKEY	257 3 13 (
	z72glzDFUwYbpcruyKn+qYSbBGDymZJBt0wSFpY05RfuG32tqSqesr98/mt8i7fa4faC8UvmL2zj
	kOsTo3t2og== ; Key ID = 26512
	)
END

ok( $ksk, 'set up ECDSA public ksk' );


my $keyfile = $ksk->privatekeyname;

END { unlink($keyfile) }


open( KSK, ">$keyfile" ) or die "$keyfile $!";
print KSK <<'END';
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: h/mc+iq9VDUbNAjQgi8S8JzlEX29IALchwJmNM3QYKk=
END
close(KSK);


my $key = new Net::DNS::RR <<'END';
ECDSAP256SHA256.example.	IN	DNSKEY	256 3 13 (
	ZVcqO8GnPFjjqXLRN8CiH1Cwx2n9s9Eg1NVXZunT5kkfwd7b7GlaliMcCPw+tZkTZNMdm8ge5Q71
	8UIKvGZMNw== ; Key ID = 24312
	)
END

ok( $key, 'set up ECDSA public key' );


my @rrset = ( $key, $ksk );
my $rrsig = create Net::DNS::RR::RRSIG( \@rrset, $keyfile );
ok( $rrsig, 'create RRSIG over rrset using private ksk' );

my $verify = $rrsig->verify( \@rrset, $ksk );
ok( $verify, 'verify RRSIG using ksk' ) || diag $rrsig->vrfyerrstr;

ok( !$rrsig->verify( \@rrset, $key ), 'verify fails using wrong key' );

my @badrrset = ($key);
ok( !$rrsig->verify( \@badrrset, $ksk ), 'verify fails using wrong rrset' );


exit;

__END__

