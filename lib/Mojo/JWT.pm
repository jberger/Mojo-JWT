package Mojo::JWT;

use Mojo::Base -base;

use Mojo::JSON qw/encode_json decode_json/;
use MIME::Base64 qw/encode_base64url decode_base64url/;

has algorithm => 'HS256';
has allow_none => 0;
has claims => sub { {} };
has secret => '';

has [qw/expires not_before/];

my $re_hs = qr/^HS(\d+)$/;
my $re_rs = qr/^RS(\d+)$/;

sub decode {
  my ($self, $token, $secret) = @_;
  $self->{token} = $token;

  # reset
  $self->algorithm(undef);
  delete $self->{$_} for qw/claims expires not_before/;

  my ($header, $claims, $signature) = split /\./, $jwt;
  my $hdata = decode_json decode_base64url($header);
  my $cdata = decode_json decode_base64url($claims);
  $signature = decode_base64url $signature;

  die 'Not a JWT' unless $hdata->{typ} eq 'JWT';
  die 'Required header field "alg" not specified'
    unless my $algo = $self->algorithm($hdata->{alg})->algorithm;

  # passed in secret can be a hash or code ref, store the result in the attribute
  if (defined $secret) {
    if(my $ref = ref $secret) {
      if ($ref eq 'HASH') {
        $secret = $secret->{$iss || die 'Issuer not specified'};
      } elsif ($ref eq 'CODE') {
        $secret = $self->$secret($cdata);
      } else {
        die 'secret not understood';
      }
    }
    $self->secret($secret);
  } else {
    $secret = $self->secret;
  }

  # check signature
  if ($algo eq 'none') {
    die 'Algorithm "none" is prohibited'
      unless $self->allow_none;
  } elsif ($algo =~ $re_rs) {
    die 'Failed RS validation'
      unless $self->verify_rsa($1, "$header.$claims", $self->secret, $signature);
  } elsif ($algo =~ $re_hs) {
    die 'failed HS validation'
      unless $signature eq $self->sign_hmac($1, "$header.$claims", $self->secret);
  } else {
    die 'Unknown algorithm';
  }

  # check timing
  my $now = time;
  if (defined(my $exp = $cdata->{exp})) {
    die 'JWT has expired' if $now > $exp;
    $self->expires($exp);
  }
  if (defined(my $nbf = $cdata->{nbf})) {
    die 'JWT is not yet valid' if $now < $nbf;
    $self->not_before($nbf);
  }

  return $self->claims($cdata)->claims;
}

sub encode {
  my $self = shift;

  my $cdata = $self->claims;
  if (defined(my $exp = $self->expires))    { $cdata->{exp} //= $exp }
  if (defined(my $nbf = $self->not_before)) { $cdata->{nbf} //= $nbf }

  my $header = encode_base64url encode_json($self->header);
  my $claims = encode_base64url encode_json($cdata);
  my $payload = "$header.$claims";
  my $signature;
  my $algo = $self->algorithm;
  if ($algo eq 'none') {
    $signature = '';
  } elsif ($algo =~ /^RS(\d+)$/) {
    $signature = $self->sign_rsa($1, $payload, $self->secret);
  } elsif ($algo =~ /^HS(\d+)$/) {
    $signature = $self->sign_hmac($1, $payload, $self->secret);
  } else {
    die 'Unknown algorithm';
  }

  return $self->{token} = "$payload." . encode_base64url $signature;
}

sub header { { typ => 'JWT', alg => shift->algorithm } }

sub sign_hmac {
  my ($self, $type, $payload, $secret) = @_;
  require Digest::SHA;
  my $f = Digest::SHA->can("hmac_sha$type") || die 'Unknown HMAC SHA algorithm';
  return $f->($payload, $secret);
}

sub sign_rsa {
  my ($self, $type, $payload, $private) = @_;
  require Crypt::OpenSSL::RSA;
  my $crypt = Crypt::OpenSSL::RSA->new_private_key($private);
  my $method = $crypt->can("use_sha${type}_hash") || die 'Unknown RSA hash algorithm';
  $crypt->$method;
  return $crypt->sign($payload);
}

sub token { shift->{token} }

sub verify_rsa {
  my ($self, $type, $payload, $public, $signature) = @_;
  my $crypt = Crypt::OpenSSL::RSA->new_public_key($public);
  my $method = $crypt->can("use_sha${type}_hash") || die 'Unknown RSA hash algorithm';
  $crypt->$method;
  return $crypt->verify($payload, $signature);
}

1;

