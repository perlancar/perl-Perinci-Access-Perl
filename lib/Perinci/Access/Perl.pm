package Perinci::Access::Perl;

use 5.010001;
use strict;
use warnings;

use URI::Split qw(uri_split);

use parent qw(Perinci::Access::Schemeless);

# AUTHORITY
# DATE
# DIST
# VERSION

sub new {
    my $class = shift;

    my $self = $class->SUPER::new(@_);

    # The pl: uri scheme has a 1:1 mapping between Perl package and path, so
    # /Foo/Bar/ must mean the Foo::Bar package. We don't allow package_prefix or
    # anything fancy like that.
    delete $self->{package_prefix};

    $self->{allow_schemes} = ['pl', ''];
    $self->{deny_schemes} = undef;

    $self;
}

sub parse_url {
    my ($self, $uri) = @_;
    die "Please specify url" unless $uri;

    my ($sch, $auth, $path) = uri_split($uri);
    $sch //= "";

    die "Only pl uri scheme is supported" unless $sch eq 'pl';
    {proto=>"pl", path=>$path};
}

1;
# ABSTRACT: Access Perl module, functions, variables through Riap

=head1 SYNOPSIS

First write your code and add Rinci metadata to them:

 package MyMod::MySubMod;

 our %SPEC;

 $SPEC{':package'} = {
     v => 1.1,
     summary => 'This package is blah blah',
 };

 $SPEC{'$var1'} = {
     v => 1.1,
     summary => 'This variable is blah blah',
 };
 our $var1;

 $SPEC{func1} = {
     v => 1.1,
     summary => 'This function does blah blah',
     args => {
         a => { schema => 'int', req => 1 },
         b => { schema => 'int' },
     },
 };
 sub func1 {
     ...
 }
 1;

then access them through Riap:

 use Perinci::Access::Perl;
 my $pa = Perinci::Access::Perl->new;

 # call function
 $res = $pa->request(call => '/MyMod/MySubMod/func1', {args=>{a=>1, b=>2}});

 # get variables
 $res = $pa->request(get => '/MyMod/MySubMod/$var1');


=head1 DESCRIPTION

This class allows you to access Perl modules, functions, and variables through
Riap. Only those which have L<Rinci> metadata are accessible. The metadata is
put in C<%SPEC> package variables, with function names as keys, or C<:package>
for package metadata, or C<$NAME> for variables. Functions will be wrapped
before executed (unless you pass C<< wrap => 0 >> to the constructor).

You should probably use this through L<Perinci::Access>.


=head1 FUNCTIONS

=head2 new(%opts) => OBJ

Constructor. For a list of options, see superclass
L<Perinci::Access::Schemeless> except for C<package_prefix> which are not
recognized by this class.

=head2 $pa->request($action, $uri, \%extras) => RESP

=head2 $pa->parse_url($url) => HASH


=head1 FAQ

=head2 Why C<%SPEC> (instead of C<%META>, C<%METADATA>, C<%RINCI>, etc)?

The name was first chosen during Sub::Spec era (see BackPAN) in 2011, it stuck.
By that time I already had had a lot of code written using C<%SPEC>.

=head2 Why wrap?

The wrapping process accomplishes several things, among others: checking of
metadata, normalization of schemas in metadata, also argument validation and
exception trapping in function.

The function wrapping introduces a small overhead when performing a sub call
(typically around several to tens of microseconds on an Intel Core i5 1.7GHz
notebook). This is usually smaller than the overhead of Perinci::Access::Perl
itself (typically in the range of 100 microseconds). But if you are concerned
about the wrapping overhead, see the C<< wrap => 0 >> option.


=head1 SEE ALSO

L<Perinci::Access::Schemeless>

L<Perinci::Access>

L<Riap>

=cut
