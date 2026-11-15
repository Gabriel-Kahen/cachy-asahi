# SPDX-License-Identifier: MIT
use strict;
use warnings;
use Config;
use Cwd qw(abs_path);
use JSON::PP ();
use List::Util qw(sum);
use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::SHA qw(sha256_hex);
use threads;
die "ambient Perl overrides\n" if grep {exists $ENV{$_}} qw(PERL5OPT PERL5LIB PERLLIB PERL_CORE PERL_SRC);
die "installed interpreter\n" unless abs_path($^X) eq '/usr/bin/perl' && "$^V" eq 'v5.42.3';
die "installed Config\n" unless abs_path($INC{'Config.pm'}) eq '/usr/lib/perl5/5.42/core_perl/Config.pm';
die "shared threaded IV64 aarch64\n" unless $Config{useshrplib} eq 'true' && $Config{useithreads} eq 'define'
    && $Config{ivsize} == 8 && $Config{archname} =~ /^aarch64-/;
die "real arithmetic/base64/thread\n" unless sum(2,3,5) == 10 && decode_base64(encode_base64('lifecycle')) eq 'lifecycle'
    && threads->create(sub { 6 * 7 })->join == 42;
open my $fh, '<', '/proc/self/maps' or die "$!\n";
my %maps;
while (<$fh>) { $maps{$1} = 1 if m{\s(/\S*libperl[^/\s]*)\s*$}; }
close $fh or die "$!\n";
die "exact installed mapped libperl\n" unless join("\n", sort keys %maps) eq '/usr/lib/perl5/5.42/core_perl/CORE/libperl.so';
print JSON::PP->new->canonical->encode({version => "$^V", interpreter => abs_path($^X),
    config_path => abs_path($INC{'Config.pm'}), config => {map { $_ => $Config{$_} } qw(cf_time useshrplib useithreads ivsize archname)},
    loaded_modules => \%INC, libperl_maps => [sort keys %maps],
    dynamic_objects => \@DynaLoader::dl_shared_objects, checks => ['arithmetic','base64','thread'],
    sha256 => sha256_hex('lifecycle')}), "\n";
