#!/usr/bin/env perl

use Mojo::Base -strict;
use Test::More;

use Mojo::JSON qw/decode_json/;
use Mojo::JWT;

my $has_rsa = eval { require Crypt::OpenSSL::RSA; 1 };
my $has_bignum = eval { require Crypt::OpenSSL::Bignum; 1 };

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
    skip 'requires Crypt::OpenSSL::RSA', 1 unless $has_rsa;
    my $name = 'encodes and decodes JWTs for RSA signaturese';
    my $rsa = Crypt::OpenSSL::RSA->generate_key(1024);
    my $payload = {foo => 'bar'};
    my $jwt = Mojo::JWT->new(claims => $payload, secret => $rsa->get_private_key_string, algorithm => 'RS512')->encode;
    my $decoded_payload = Mojo::JWT->new(public => $rsa->get_public_key_string)->decode($jwt);
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

{
    my $name = 'raises exception with empty hmac key';
    my $right_secret = 'foo';
    my $bad_secret = '';
    my $payload = {foo => 'bar'};
    my $jwt_message = Mojo::JWT->new(claims => $payload, secret => $right_secret, algorithm => 'HS256')->encode;
    eval {
        Mojo::JWT->new(secret => $bad_secret)->decode($jwt_message);
    };
    like $@, qr/^symmetric secret not specified/, $name;
}

SKIP: {
    skip 'requires Crypt::OpenSSL::RSA', 1 unless $has_rsa;
    my $name = 'raises exception with wrong rsa key';
    my $right_rsa = Crypt::OpenSSL::RSA->generate_key(1024);
    my $bad_rsa = Crypt::OpenSSL::RSA->generate_key(1024);
    my $payload = {foo => 'bar'};
    my $jwt = Mojo::JWT->new(claims => $payload, secret => $right_rsa->get_private_key_string, algorithm => 'RS256')->encode;
    eval {
        Mojo::JWT->new(public => $bad_rsa->get_public_key_string)->decode($jwt);
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

SKIP: {
    skip 'requires Crypt::OpenSSL::Bignum', 1 unless $has_bignum;
    my $name = 'decodes JWT with jwks';
    my $jwk = '{"kty":"RSA","e":"AQAB","kid":"test","n":"nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw"}';
    my $payload = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.fkLIy_Zvkt7wS6YhOqcaPkyqHK0hMwd1qBNoysXpWlt2fsArf-_ZwmDP8Qao23XPpY1lHrRRuXCpf_Fyyv8eBDYFTtopqkoXeaFPK2ERjCiK6dvOGeLwY5hXu-itTpueqdpeM2GTPS6Eu_JAtYe-wyztnS14BbCZrUCXJCOyuP4Kp78Hw0LfsiXwRb0OsHmefK7BrWJCptPTShVSu2UP0wPL5wBR0MEJIdp7fMcyqSVxmzYeaVxw_prTy655CmhanciawRgqx4ccTIRsfKR_s3SiatsPUeWqGfW2NsVgpzVRGUuOgBOOav6Bk7etb3U3wxAURyAW-9RZV6fsOpShbA';

    my $jwt = Mojo::JWT->new(jwks => [decode_json $jwk]);
    $jwt->decode($payload);
    my $expected_claims = {sub => '1234567890', name => 'John Doe', admin => Mojo::JSON::true, iat => 1516239022};
    is_deeply $jwt->claims, $expected_claims, $name;
}

SKIP: {
    skip 'requires Crypt::OpenSSL::Bignum', 1 unless $has_bignum;
    my $name = 'should not decode JWT with missing kid if trying against jwks';
    my $jwk = '{"kty":"RSA","e":"AQAB","kid":"test","n":"nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw"}';
    my $payload = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA';

    my $jwt = Mojo::JWT->new(jwks => [decode_json $jwk]);
    eval {
        $jwt->decode($payload);
    };
    like $@, qr/^public key not specified/, $name;
}

SKIP: {
    skip 'requires Crypt::OpenSSL::Bignum', 1 unless $has_bignum;
    my $name = 'should not decode JWT without JWK';
    my $jwk = '{"kty":"RSA","e":"AQAB","kid":"test-other","n":"nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw"}';
    my $payload = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.fkLIy_Zvkt7wS6YhOqcaPkyqHK0hMwd1qBNoysXpWlt2fsArf-_ZwmDP8Qao23XPpY1lHrRRuXCpf_Fyyv8eBDYFTtopqkoXeaFPK2ERjCiK6dvOGeLwY5hXu-itTpueqdpeM2GTPS6Eu_JAtYe-wyztnS14BbCZrUCXJCOyuP4Kp78Hw0LfsiXwRb0OsHmefK7BrWJCptPTShVSu2UP0wPL5wBR0MEJIdp7fMcyqSVxmzYeaVxw_prTy655CmhanciawRgqx4ccTIRsfKR_s3SiatsPUeWqGfW2NsVgpzVRGUuOgBOOav6Bk7etb3U3wxAURyAW-9RZV6fsOpShbA';

    my $jwt = Mojo::JWT->new(jwks => [decode_json $jwk]);
    eval {
        $jwt->decode($payload);
    };
    like $@, qr/^public key not specified/, $name;
}

done_testing;
