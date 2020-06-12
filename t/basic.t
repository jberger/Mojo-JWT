#!/usr/bin/env perl

use Mojo::Base -strict;
use Test::More;

use Mojo::JWT;

my $has_rsa = eval { require Crypt::PK::RSA; 1 };
my $has_ecc = eval { require Crypt::PK::ECC; 1 };


{
    my $name = 'encodes and decodes JWTs';
    my $secret = 'secret';
    my $payload = {foo => 'bar'};
    my $jwt = Mojo::JWT->new(claims => $payload, secret => $secret)->encode;
    my $decoded_payload = Mojo::JWT->new(secret => $secret)->decode($jwt);
    is_deeply $decoded_payload, $payload, $name;
}

{
    no warnings 'once';
    no warnings 'redefine';
    my $now = time;
    local *Mojo::JWT::now = sub { $now };

    my $name = 'encodes and decodes JWTs (set_iat)';
    my $secret = 'secret';
    my $payload = {foo => 'bar'};
    my $jwt = Mojo::JWT->new(claims => $payload, secret => $secret, set_iat => 1)->encode;
    my $decoded_payload = Mojo::JWT->new(secret => $secret)->decode($jwt);
    is_deeply $decoded_payload, $payload, $name;
    is $decoded_payload->{iat}, $now, 'included correct iat';
}

{
    my $name = 'encodes and decodes JWTs for HS512 signaturese';
    my $payload = {foo => 'bar'};
    my $jwt = Mojo::JWT->new(claims => $payload, secret => 'S3cR3t', algorithm => 'HS512')->encode;
    my $decoded_payload = Mojo::JWT->new(secret => 'S3cR3t')->decode($jwt);
    is_deeply $decoded_payload, $payload, $name;
}

SKIP: {
    skip 'requires Crypt::PK::RSA', 1 unless $has_rsa;
    my $name = 'encodes and decodes JWTs for RSA signaturese';
    my $rsa = Crypt::PK::RSA->new();
    $rsa->generate_key(128,65537);
    my $payload = {foo => 'bar'};
    my $jwt = Mojo::JWT->new(claims => $payload, secret => $rsa->export_key_pem('private'), algorithm => 'RS512')->encode;
    my $decoded_payload = Mojo::JWT->new(public => $rsa->export_key_pem('public'))->decode($jwt);
    is_deeply $decoded_payload, $payload, $name;
}

SKIP: {
    skip 'requires Crypt::PK::ECC', 1 unless $has_ecc;
    my $name = 'encodes and decodes JWTs for ECC signaturese';
    my $ecc = Crypt::PK::ECC->new();
    $ecc->generate_key('secp384r1');
    my $payload = {foo => 'bar'};
    my $jwt = Mojo::JWT->new(claims => $payload, secret => $ecc->export_key_pem('private'), algorithm => 'ES512')->encode;
    my $decoded_payload = Mojo::JWT->new(public => $ecc->export_key_pem('public'))->decode($jwt);
    is_deeply $decoded_payload, $payload, $name;
}

{
    my $name = 'decodes valid JWTs';
    my $example_payload = {hello => 'world'};
    my $example_secret = 'secret';
    my $example_jwt = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8';
    my $decoded_payload = Mojo::JWT->new(secret => $example_secret)->decode($example_jwt);
    is_deeply $decoded_payload, $example_payload, $name;
}

{
    my $name = 'raises exception with wrong hmac key';
    my $right_secret = 'foo';
    my $bad_secret = 'bar';
    my $payload = {foo => 'bar'};
    my $jwt_message = Mojo::JWT->new(claims => $payload, secret => $right_secret, algorithm => 'HS256')->encode;
    eval {
        Mojo::JWT->new(secret => $bad_secret)->decode($jwt_message);
    };
    like $@, qr/^Failed HS validation/, $name;
}

SKIP: {
    skip 'requires Crypt::OpenSSL::RSA', 1 unless $has_rsa;
    my $name = 'raises exception with wrong rsa key';
    my $right_rsa = Crypt::PK::RSA->new;
    $right_rsa->generate_key(128,65537);
    my $bad_rsa = Crypt::PK::RSA->new;
    $bad_rsa->generate_key(128,65537);
    my $payload = {foo => 'bar'};
    my $jwt = Mojo::JWT->new(claims => $payload, secret => $right_rsa->export_key_pem('private'), algorithm => 'RS256')->encode;
    eval {
        Mojo::JWT->new(public => $bad_rsa->export_key_pem('public'))->decode($jwt);
    };
    like $@, qr/^Failed RS validation/, $name;
}

{
    my $name = 'allows decoding without key';
    my $payload = {foo => 'bar'};
    my $jwt = Mojo::JWT->new(claims => $payload, algorithm => 'none')->encode;
    my $decoded_payload = Mojo::JWT->new(allow_none => 1)->decode($jwt);
    is_deeply $decoded_payload, $payload, $name;
}

{
    my $name = 'raises exception on unsupported crypto algorithm';
    my $payload = {foo => 'bar'};
    eval {
        Mojo::JWT->new(claims => $payload, secret => 'secret', algorithm => 'HS131')->encode;
    };
    like $@, qr/^Unsupported HS signing algorithm/, $name;
}

{
    my $name = 'encodes and decodes JWTs with custom headers';
    my $secret = 'secret';
    my $payload = { foo => 'bar' };
    my $header  = { x5c => [ 'some-value' ] };
    my $encoded_jwt = Mojo::JWT->new(claims => $payload,secret => $secret, header => $header)->encode;
    my $jwt = Mojo::JWT->new(secret => $secret);
    $jwt->decode($encoded_jwt);
    my $expected_header = { x5c => [ 'some-value' ] };
    is_deeply $jwt->header, $expected_header, $name;
}

{
    my $name = 'should not be able to override "typ" header';
    my $secret = 'secret';
    my $payload = { foo => 'bar' };
    my $header  = { typ => 'JWS', x5c =>  [ 'some-value'] };
    my $encoded_jwt = Mojo::JWT->new(claims => $payload,secret => $secret, header => $header)->encode;
    my $jwt = Mojo::JWT->new(secret => $secret);
    $jwt->decode($encoded_jwt);
    my $expected_header = { x5c => [ 'some-value' ] };
    is_deeply $jwt->header, $expected_header, $name;
}

done_testing;
