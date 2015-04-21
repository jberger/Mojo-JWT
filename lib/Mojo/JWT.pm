package Mojo::JWT;

use Mojo::Base -base;

use Mojo::JSON qw/encode_json decode_json/;
use MIME::Base64 qw/encode_base64url decode_base64url/;

use Carp;

has algorithm => 'HS256';
has allow_none => 0;
has claims => sub { {} };
has [qw/expires not_before/];
has [qw/public secret/] => '';

my $re_hs = qr/^HS(\d+)$/;
my $re_rs = qr/^RS(\d+)$/;

sub decode {
  my ($self, $token, $peek) = @_;
  $self->{token} = $token;

  # reset
  $self->algorithm(undef);
  delete $self->{$_} for qw/claims expires not_before/;

  my ($hstring, $cstring, $signature) = split /\./, $token;
  my $header = decode_json decode_base64url($hstring);
  my $claims = decode_json decode_base64url($cstring);
  $signature = decode_base64url $signature;

  croak 'Not a JWT' unless $header->{typ} eq 'JWT';
  croak 'Required header field "alg" not specified'
    unless my $algo = $self->algorithm($header->{alg})->algorithm;

  $self->$peek($claims) if $peek;

  # check signature
  my $payload = "$hstring.$cstring";
  if ($algo eq 'none') {
    croak 'Algorithm "none" is prohibited'
      unless $self->allow_none;
  } elsif ($algo =~ $re_rs) {
    croak 'Failed RS validation'
      unless $self->verify_rsa($1, $payload, $signature);
  } elsif ($algo =~ $re_hs) {
    croak 'Failed HS validation'
      unless $signature eq $self->sign_hmac($1, $payload);
  } else {
    croak 'Unsupported signing algorithm';
  }

  # check timing
  my $now = time;
  if (defined(my $exp = $claims->{exp})) {
    croak 'JWT has expired' if $now > $exp;
    $self->expires($exp);
  }
  if (defined(my $nbf = $claims->{nbf})) {
    croak 'JWT is not yet valid' if $now < $nbf;
    $self->not_before($nbf);
  }

  return $self->claims($claims)->claims;
}

sub encode {
  my $self = shift;
  delete $self->{token};

  my $claims = $self->claims;
  if (defined(my $exp = $self->expires))    { $claims->{exp} = $exp }
  if (defined(my $nbf = $self->not_before)) { $claims->{nbf} = $nbf }

  my $hstring = encode_base64url encode_json($self->header);
  my $cstring = encode_base64url encode_json($claims);
  my $payload = "$hstring.$cstring";
  my $signature;
  my $algo = $self->algorithm;
  if ($algo eq 'none') {
    $signature = '';
  } elsif ($algo =~ $re_rs) {
    $signature = $self->sign_rsa($1, $payload);
  } elsif ($algo =~ $re_hs) {
    $signature = $self->sign_hmac($1, $payload);
  } else {
    croak 'Unknown algorithm';
  }

  return $self->{token} = "$payload." . encode_base64url $signature;
}

sub header { { typ => 'JWT', alg => shift->algorithm } }

sub sign_hmac {
  my ($self, $size, $payload) = @_;
  require Digest::SHA;
  my $f = Digest::SHA->can("hmac_sha$size") || croak 'Unsupported HS signing algorithm';
  return $f->($payload, $self->secret);
}

sub sign_rsa {
  my ($self, $size, $payload) = @_;
  require Crypt::OpenSSL::RSA;
  my $crypt = Crypt::OpenSSL::RSA->new_private_key($self->secret || croak 'private key (secret) not specified');
  my $method = $crypt->can("use_sha${size}_hash") || croak 'Unsupported RS signing algorithm';
  $crypt->$method;
  return $crypt->sign($payload);
}

sub token { shift->{token} }

sub verify_rsa {
  my ($self, $size, $payload, $signature) = @_;
  require Crypt::OpenSSL::RSA;
  my $crypt = Crypt::OpenSSL::RSA->new_public_key($self->public || croak 'public key not specified');
  my $method = $crypt->can("use_sha${size}_hash") || croak 'Unsupported RS verification algorithm';
  $crypt->$method;
  return $crypt->verify($payload, $signature);
}

1;

=head1 NAME

Mojo::JWT - JSON Web Token the Mojo way

=head1 SYNOPSIS

  my $jwt = Mojo::JWT->new(claims => {...}, secret => 's3cr3t')->encode;
  my $claims = Mojo::JWT->new(secret => 's3cr3t')->decode($jwt);

=head1 DESCRIPTIION

JSON Web Token is described in L<https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32>.
L<Mojo::JWT> implements that standard with an API that should feel familiar to L<Mojolicious> users (though of course it is useful elsewhere).
Indeed, JWT is much like L<Mojolicious::Sessions> except that the result is a url-safe text string rather than a cookie.

In JWT, the primary payload is called the C<claims>, and a few claims are reserved, as seen in the IETF document.
The header and the claims are signed when stringified to guard against tampering.
Note that while signed, the data is not encrypted, so don't use it to send secrets over clear channels.

=head1 ATTRIBUTES

L<Mojo::JWT> inherits all of the attributes from L<Mojo::Base> and implements the following new ones.

=head2 algorithm

The algorithm to be used to sign a JWT during encoding or else the algorithm that was used for the most recent decoding.
Defaults to C<HS256> until a decode is performed.

C<none> is an acceptable encoding algorithm, however for it to be used to decode, L</allow_none> must be set.

=head2 allow_none

To prevent spoofing attacks, C<allow_none> must be explicitly set to a true value otherwise decoding a JWT which specifies the C<none> algorithm will result in an exception.
The default is of course false.

=head2 claims

The payload to be encoded or else the claims from the most recent decoding.
This must be a hash reference, array references are not allowed as the top-level JWT claims.

=head2 expires

The epoch time value after which the JWT value should not be considered valid.
This value (if set and not undefined) will be used as the C<exp> key in the claims or was extracted from the claims during the most recent decoding.

=head2 not_before

The epoch time value before which the JWT value should not be considered valid.
This value (if set and not undefined) will be used as the C<nbf> key in the claims or was extracted from the claims during the most recent decoding.

=head2 public

The public key to be used in decoding an asymmetrically signed JWT (eg. RSA).

=head2 secret

The symmetric secret (eg. HMAC) or else the private key used in encoding an asymmetrically signed JWT (eg. RSA).

=head1 METHODS

L<Mojo::JWT> inherits all of the methods from L<Mojo::Base> and implements the following new ones.

=head2 decode

  my $claims = $jwt->decode($token);

  my $peek = sub { my ($jwt, $claims) = @_; ... };
  my $claims = $jwt->decode($token, $peek);

Decode and parse a JSON Web Token string and return the claims hashref.
Calling this function immediately sets the L</token> to the passed in token.
It also sets L</algorithm> to C<undef> and unsets L</claims>, L</expires> and L</not_before>.
These values are then set as part of the parsing process.

Parsing occurs as follows

=over

=item *

The L</algorithm> is extracted from the header and set, if not present or permissible an exception is thrown

=item *

If a C<$peek> callback is provided, it is called with the instance and claims as arguments

=item *

The signature is verified or an exception is thrown

=item *

The timing claims (L</expires> and L</not_before>), if present, are evaluated, failures result in exceptions. On success the values are set in the relevant attributes

=item *

The L</claims> attribute is set and the claims are returned.

=back

Note that when the C<$peek> callback is invoked, the claims have not yet been verified.
This callback is most likely to be used to inspect the C<iss> or issuer claim to determine a secret or key for decoding.
The return value is ignored, changes should be made to the instances attributes directly.
Since the L</algorithm> has already been parsed, it is available via the instance attribute as well.

=head2 encode

  my $token = $jwt->encode;

Encode the data expressed in the instance attributes: L</algorithm>, L</claims>, L</expires>, L</not_before>.
Note that if the timing attributes are given, they override existing keys in the L</claims>.
Calling C<encode> immediately clears the L</token> and upon completion sets it to the result as well as returning it.

Note also that due to Perl's hash randomization, repeated encoding is not guaranteed to result in the same encoded string.
However any encoded string will survive an encode/decode roundtrip.

=head2 header

  my $header = $jwt->header;

Returns a hash reference representing the JWT header, constructed from instance attributes (see L</algorithm>).

=head2 sign_hmac

  my $signature = $jwt->sign_hmac($size, $payload);

Returns the HMAC SHA signature for the given size and payload.
The L</secret> attribute is used as the symmetric key.
The result is not yet base64 encoded.
This method is provided mostly for the purposes of subclassing.

=head2 sign_rsa

  my $signature = $jwt->sign_rsa($size, $payload);

Returns the RSA signature for the given size and payload.
The L</secret> attribute is used as the private key.
The result is not yet base64 encoded.
This method is provided mostly for the purposes of subclassing.

=head2 token

The most recently encoded or decoded token.
Note that any attribute modifications are not taken into account until L</encode> is called again.

=head2 verify_rsa

  my $bool = $jwt->verify_rsa($size, $payload, $signature);

Returns true if the given RSA size algorithm validates the given payload and signature.
The L</public> attribute is used as the public key.
This method is provided mostly for the purposes of subclassing.

=head1 SEE ALSO

=over

=item L<Acme::JWT>

=item L<JSON::WebToken>

=item L<http://jwt.io/>

=back

=head1 SOURCE REPOSITORY

L<http://github.com/jberger/Mojo-JWT>

=head1 AUTHOR

Joel Berger, E<lt>joel.a.berger@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2015 by Joel Berger

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

