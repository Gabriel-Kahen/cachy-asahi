# SPDX-License-Identifier: MIT
package CachyAsahi::Perl5423::Fixture;
BEGIN {
    my $r = $ENV{CACHY_XS_ROOT} // die "explicit admitted root required\n";
    die "literal disposable root required\n" unless $r =~ m{\A/[A-Za-z0-9._+/-]+\z} && $r !~ m{(?:\A|/)\.\.?(?:/|\z)|//} && $r ne '/';
    @INC = ("$r/usr/lib/perl5/5.42/core_perl", "$r/usr/share/perl5/core_perl");
}
use strict;
use warnings;
use Config;
use Cwd qw(abs_path);
use Digest::SHA qw(sha256_hex);
use JSON::PP ();
use File::Find ();
use Fcntl qw(:DEFAULT :mode);
use ExtUtils::MakeMaker ();

sub raw {
    my ($path, $cap) = @_;
    sysopen my $fh, $path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK or die "read $path: $!\n";
    my @before = stat $fh;
    die "ordinary bounded single-link file required: $path\n" unless S_ISREG($before[2]) && $before[3] == 1 && $before[7] <= $cap;
    binmode $fh; my $body = '';
    while (1) { my $n = sysread $fh, my $part, 65536; die "read $path: $!\n" unless defined $n; last unless $n; $body .= $part; die "file cap\n" if length($body) > $cap; }
    my @after = stat $fh; close $fh or die "close: $!\n"; my @leaf = lstat $path;
    die "file changed during read\n" unless length($body) == $before[7] && join(':', @before[0..3,7,9,10]) eq join(':', @after[0..3,7,9,10]) && join(':', @before[0..3,7,9,10]) eq join(':', @leaf[0..3,7,9,10]);
    return $body;
}
sub pinned {
    my ($path, $pin) = @_; die "bounded pinned file required\n" unless "$pin->{bytes}" =~ /\A[0-9]+\z/ && $pin->{bytes} <= 64*1024*1024;
    my $body = raw($path, $pin->{bytes});
    die "pinned bytes differ: $path\n" unless length($body) == $pin->{bytes} && sha256_hex($body) eq $pin->{sha256};
    die "pinned mode differs\n" if exists($pin->{mode}) && ((lstat $path)[2] & 07777) != $pin->{mode};
    return $body;
}
sub check {
    my ($phase) = @_; die "fixed phase\n" unless $phase eq 'configure' || $phase eq 'runtime';
    die "ambient Perl overrides refused\n" if grep {exists $ENV{$_}} qw(PERL5OPT PERL5LIB PERLLIB PERL_CORE PERL_SRC PERL_MM_OPT PERL_MB_OPT PERL_LOCAL_LIB_ROOT);
    my %operand;
    for my $key (qw(ADMISSION INPUTS)) {
        my $path = $ENV{'CACHY_XS_'.$key} // die "explicit $key operand required\n";
        my $body = raw($path, 4*1024*1024); die "operand SHA required\n" unless sha256_hex($body) eq ($ENV{'CACHY_XS_'.$key.'_SHA256'} // '');
        $operand{$key} = JSON::PP->new->decode($body);
    }
    my ($a, $inputs) = @operand{qw(ADMISSION INPUTS)}; my $root = $ENV{CACHY_XS_ROOT};
    die "actual admitted root required\n" unless $a->{schema} == 1 && $inputs->{schema} == 1 && $a->{root}{path} eq $root && abs_path($root) eq $root && $root ne '/' && $a->{root}{kind} =~ /\A(?:extracted|installed)\z/;
    my @s = stat $root; die "root identity differs\n" unless $s[4] == $a->{root}{owner_uid} && $s[4] == $< && $s[0] == $a->{root}{device} && $s[1] == $a->{root}{inode};
    die "exact candidate required\n" unless $a->{candidate}{commit} eq 'c8e9baea97f83f652763e701143d6dec5b679f31' && $a->{candidate}{recipe_sha256} eq 'cf0df8990ac83f48a4c29978c932922108f0e01cb6d052209934da5b01af4068' && $a->{candidate}{source_sha256} eq '16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725';
    die "input/archive identity differs\n" unless $inputs->{archive_sha256} eq $a->{archive}{sha256} && $inputs->{candidate_recipe_sha256} eq $a->{candidate}{recipe_sha256} && $a->{inputs_sha256} eq $ENV{CACHY_XS_INPUTS_SHA256};
    die "fixed target archive required\n" unless $a->{target_arch} =~ /\A(?:aarch64|x86_64)\z/ && $a->{archive}{name} eq "perl-5.42.3-1.3-$a->{target_arch}.pkg.tar.zst";
    my $artifact = $a->{artifact};
    die "actual artifact scope required\n" unless ($artifact->{kind} eq 'host' && $a->{target_arch} eq 'x86_64' && !grep {defined $artifact->{$_}} qw(source run job)) || ($artifact->{kind} eq 'native' && $a->{target_arch} eq 'aarch64' && ($artifact->{source} // '') =~ /\A[0-9a-f]{40}\z/ && !grep {($artifact->{$_} // '') !~ /\A[1-9][0-9]*\z/} qw(run job));
    pinned($a->{archive}{path}, $a->{archive}); pinned($a->{inventory}{path}, $a->{inventory});
    my $pkg = pinned($a->{metadata}{pkginfo}{path}, $a->{metadata}{pkginfo}); my $build = pinned($a->{metadata}{buildinfo}{path}, $a->{metadata}{buildinfo});
    die "exact package metadata required\n" unless $pkg =~ /^pkgname = perl$/m && $pkg =~ /^pkgver = 5\.42\.3-1\.3$/m && $pkg =~ /^arch = \Q$a->{target_arch}\E$/m && $build =~ /^pkgver = 5\.42\.3-1\.3$/m && $build =~ /^pkgarch = \Q$a->{target_arch}\E$/m && $build =~ /^pkgbuild_sha256sum = \Q$a->{candidate}{recipe_sha256}\E$/m;
    my ($arch, $pure) = ("$root/usr/lib/perl5/5.42/core_perl", "$root/usr/share/perl5/core_perl"); my $core = "$arch/CORE";
    die "actual candidate interpreter/CORE required\n" unless $ENV{CACHY_XS_PERL} eq "$root/usr/bin/perl" && abs_path($^X) eq $ENV{CACHY_XS_PERL} && $ENV{CACHY_XS_CORE} eq $core;
    die "candidate shared threaded IV64 configuration required\n" unless "$^V" eq 'v5.42.3' && $Config{cf_time} eq 'Sun Aug  2 00:00:00 UTC 2026' && $Config{useshrplib} eq 'true' && $Config{useithreads} eq 'define' && $Config{ivsize} == 8 && abs_path($INC{'Config.pm'}) eq "$arch/Config.pm" && $Config{archname} =~ /\A\Q$a->{target_arch}\E-/ && $ExtUtils::MakeMaker::VERSION eq '7.76';
    my %found = ('usr/bin/perl' => 1);
    File::Find::find({no_chdir => 1, wanted => sub {die "runtime alias\n" if -l $_; return if -d _; die "runtime special file\n" unless -f _; $found{substr($File::Find::name, length($root)+1)} = 1;}}, $arch, $pure);
    die "closed admitted runtime/header trees required\n" unless join("\n", sort keys %found) eq join("\n", sort keys %{$inputs->{files}});
    pinned("$root/$_", $inputs->{files}{$_}) for sort keys %found;
    my %tools;
    for my $tool (qw(cc ld make)) {my $path = $ENV{'CACHY_XS_'.uc($tool)} // ''; die "explicit admitted tool required\n" unless $path =~ m{\A/[A-Za-z0-9._+/-]+\z} && $path eq $a->{toolchain}{$tool}{path}; pinned($path, $a->{toolchain}{$tool}); $tools{$tool} = $a->{toolchain}{$tool};}
    my $cwd = abs_path('.'); my %inc;
    for my $key (sort keys %INC) {my $path = abs_path($INC{$key}) // die "unresolved loaded module\n"; my $relative = substr($path, length($root)+1); die "baseline module substituted: $key\n" unless (index($path, "$root/") == 0 && $found{$relative}) || $path eq "$cwd/provenance.pl" || ($phase eq 'runtime' && $path eq "$cwd/blib/lib/CachyAsahi/Perl5423/Consumer.pm"); $inc{$key} = $path;}
    my @objects = map {abs_path($_) // die "unresolved dynamic object\n"} @DynaLoader::dl_shared_objects;
    my $extension = "$cwd/blib/arch/auto/CachyAsahi/Perl5423/Consumer/Consumer.so";
    for my $path (@objects) {die "baseline dynamic object substituted\n" unless (index($path, "$root/") == 0 && $found{substr($path, length($root)+1)}) || ($phase eq 'runtime' && $path eq $extension);}
    die "actual fixture extension not loaded\n" if $phase eq 'runtime' && !grep {$_ eq $extension} @objects;
    open my $proc, '<:raw', '/proc/self/maps' or die "actual process maps: $!\n";
    my $maps = ''; while (1) {my $n = read($proc, my $part, 65536); die "process maps read: $!\n" unless defined $n; last unless $n; $maps .= $part; die "bounded process maps\n" if length($maps) > 1024*1024;} close $proc or die "process maps close: $!\n";
    my %libperl;
    for (split /\n/, $maps) { $libperl{$1} = 1 if m{\s(/\S*libperl[^/\s]*)\z}; }
    die "actual admitted libperl mapping required\n" unless join("\n", sort keys %libperl) eq "$core/libperl.so";
    my $deps;
    if ($phase eq 'runtime') {$deps = raw('consumer.d', 1024*1024); for my $header (qw(EXTERN.h perl.h XSUB.h config.h patchlevel.h)) {die "candidate header dependency required: $header\n" unless $deps =~ /\Q$core\/$header\E(?:\s|\z)/;}}
    my @selected = ('usr/bin/perl', map {"usr/lib/perl5/5.42/core_perl/$_"} ('Config.pm', map {"CORE/$_"} qw(perl.h EXTERN.h XSUB.h config.h patchlevel.h libperl.so)));
    return {schema => 1, phase => $phase, native_acceptance => JSON::PP::false, admission_sha256 => $ENV{CACHY_XS_ADMISSION_SHA256}, inputs_sha256 => $ENV{CACHY_XS_INPUTS_SHA256}, archive => $a->{archive}, artifact => $a->{artifact}, inventory => $a->{inventory}, perl => $ENV{CACHY_XS_PERL}, root => $a->{root}, core => $core, arch => $arch, pure => $pure, version => "$^V", config => {map {$_ => $Config{$_}} qw(cf_time useshrplib useithreads ivsize archname cc ccflags ld lddlflags libperl)}, make_maker => $ExtUtils::MakeMaker::VERSION, tools => \%tools, loaded_modules => \%inc, dynamic_objects => \@objects, libperl_maps => [sort keys %libperl], runtime_files => {map {$_ => $inputs->{files}{$_}} @selected}, extension => $phase eq 'runtime' ? $extension : undef, extension_sha256 => $phase eq 'runtime' ? sha256_hex(raw($extension, 64*1024*1024)) : undef, dependencies_sha256 => defined($deps) ? sha256_hex($deps) : undef};
}
sub receipt {my ($path, $facts, $extra) = @_; open my $fh, '>:raw', $path or die "receipt: $!\n"; print {$fh} JSON::PP->new->canonical->pretty->encode({%$facts, %$extra}); close $fh or die "receipt close: $!\n";}
unless (caller) {
    check('configure'); unshift @INC, abs_path('blib/arch'), abs_path('blib/lib');
    require CachyAsahi::Perl5423::Consumer;
    print JSON::PP->new->canonical->pretty->encode({%{check('runtime')}, api => CachyAsahi::Perl5423::Consumer::native_info()});
}
1;
