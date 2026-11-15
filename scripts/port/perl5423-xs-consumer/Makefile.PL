# SPDX-License-Identifier: MIT
BEGIN {
    my $r = $ENV{CACHY_XS_ROOT} // die "explicit admitted root required\n";
    die "literal disposable root required\n" unless $r =~ m{\A/[A-Za-z0-9._+/-]+\z} && $r !~ m{(?:\A|/)\.\.?(?:/|\z)|//} && $r ne '/';
    @INC = ("$r/usr/lib/perl5/5.42/core_perl", "$r/usr/share/perl5/core_perl");
}
use strict;
use warnings;
use ExtUtils::MakeMaker;
require './provenance.pl';
die "MakeMaker overrides refused\n" if @ARGV;
my $facts = CachyAsahi::Perl5423::Fixture::check('configure');
my ($perl, $core, $arch, $pure) = @{$facts}{qw(perl core arch pure)};
my $run = "$perl -I$arch -I$pure";
my $mm = WriteMakefile(
    NAME => 'CachyAsahi::Perl5423::Consumer', VERSION_FROM => 'lib/CachyAsahi/Perl5423/Consumer.pm',
    MIN_PERL_VERSION => '5.042003', LICENSE => 'mit', XS => {'Consumer.xs' => 'Consumer.c'},
    PERL => $run, FULLPERL => $run, PERL_LIB => $pure, PERL_ARCHLIB => $arch, PERL_INC => $core, PERL_CORE => 0,
    CC => $ENV{CACHY_XS_CC}, LD => $ENV{CACHY_XS_LD}, MAKE => $ENV{CACHY_XS_MAKE},
    INC => "-I$core", MYEXTLIB => "$core/libperl.so", LIBS => [],
    CCFLAGS => "$Config::Config{ccflags} -MMD -MF consumer.d", MAN3PODS => {},
    clean => {FILES => 'consumer.d'},
);
die "MakeMaker selected other headers or library\n" if $mm->{PERL_SRC} || $mm->{PERL_CORE}
    || $mm->{PERL_INC} ne $core || $mm->{PERL_ARCHLIB} ne $arch || $mm->{PERL_LIB} ne $pure || $mm->{MYEXTLIB} ne "$core/libperl.so";
die "MakeMaker substituted interpreter or toolchain\n" unless $mm->{PERL} eq qq{"$perl" -I$arch -I$pure} && $mm->{FULLPERL} eq $run
    && $mm->{CC} eq $ENV{CACHY_XS_CC} && $mm->{LD} eq $ENV{CACHY_XS_LD} && $mm->{MAKE} eq $ENV{CACHY_XS_MAKE};
CachyAsahi::Perl5423::Fixture::receipt('xs-configure-provenance.json', $facts,
    {makefile => {map {$_ => $mm->{$_}} qw(PERL FULLPERL PERL_INC PERL_LIB PERL_ARCHLIB CC LD MAKE MYEXTLIB CCFLAGS)}});
