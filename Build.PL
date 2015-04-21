#!/usr/bin/env perl

use strict;
use warnings;

use Module::Build;

my $build = Module::Build->new(
  module_name        => 'Mojo::JWT',
  dist_author        => 'Joel Berger <joel.a.berger@gmail.com>',
  license            => 'perl',
  configure_requires => { 'Module::Build' => 0.38 },
  requires => {
    'Mojolicious'  => '5.00',
    'Digest::SHA'  => 0,
    'MIME::Base64' => 0,
  },
  recommends => {
    'Crypt::OpenSSL::RSA' => 0,
  },
  meta_merge => {
    resources => {
      repository => 'https://github.com/jberger/Mojo-JWT',
      bugtracker => 'https://github.com/jberger/Mojo-JWT/issues',
    },
  },
);

$build->create_build_script;
