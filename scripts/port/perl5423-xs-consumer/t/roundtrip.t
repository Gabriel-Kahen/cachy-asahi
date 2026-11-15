# SPDX-License-Identifier: MIT
BEGIN {
    my $r = $ENV{CACHY_XS_ROOT} // die "explicit admitted root required\n";
    die "literal disposable root required\n" unless $r =~ m{\A/[A-Za-z0-9._+/-]+\z} && $r !~ m{(?:\A|/)\.\.?(?:/|\z)|//} && $r ne '/';
    @INC = ("$r/usr/lib/perl5/5.42/core_perl", "$r/usr/share/perl5/core_perl");
    require Cwd;
    unshift @INC, Cwd::abs_path('blib/arch'), Cwd::abs_path('blib/lib');
}
use strict;
use warnings;
use Test::More;
use Config;
use CachyAsahi::Perl5423::Consumer;
require './provenance.pl';
is($CachyAsahi::Perl5423::Consumer::VERSION, '0.001', 'loaded fixture version');
my $api = CachyAsahi::Perl5423::Consumer::native_info();
is_deeply($api, {perl => '5.42.3', api => join('.', @Config{qw(api_revision api_version api_subversion)}), iv_bytes => 8}, 'actual compiled headers and Perl API');
for my $value (undef, 0, -7, '', "nul\0bytes", "\x{e9}\x{1f642}\0tail") {
    my $copy = CachyAsahi::Perl5423::Consumer::scalar_roundtrip($value);
    is($copy, $value, 'XS scalar/string roundtrip');
    is(utf8::is_utf8($copy), utf8::is_utf8($value), 'XS UTF8 flag preserved');
}
for my $value (0, -1, 9_223_372_036_854_775_807, -9_223_372_036_854_775_807 - 1) {
    is(CachyAsahi::Perl5423::Consumer::iv_roundtrip($value), $value, 'native signed IV roundtrip');
}
my $values = [undef, -17, "a\0b", "\x{e9}\x{1f642}"];
my $copy = CachyAsahi::Perl5423::Consumer::array_roundtrip($values);
is_deeply($copy, $values, 'XS array roundtrip');
is(utf8::is_utf8($copy->[3]), utf8::is_utf8($values->[3]), 'array UTF8 flag preserved');
my $facts = CachyAsahi::Perl5423::Fixture::check('runtime');
is($facts->{extension}, Cwd::abs_path('blib/arch/auto/CachyAsahi/Perl5423/Consumer/Consumer.so'), 'actual loaded XS object');
CachyAsahi::Perl5423::Fixture::receipt('xs-runtime-provenance.json', $facts, {api => $api, assertions => 'SCALAR_NUL_UTF8_ARRAY_IV64'});
done_testing();
