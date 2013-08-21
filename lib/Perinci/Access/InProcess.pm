package Perinci::Access::InProcess;

use 5.010001;
use strict;
use warnings;
use Log::Any '$log';

use parent qw(Perinci::Access::Base);

use Perinci::Object;
use Scalar::Util qw(blessed reftype);
use SHARYANTO::Package::Util qw(package_exists);
use URI;
use UUID::Random;

# VERSION

our $re_perl_package =
    qr/\A[A-Za-z_][A-Za-z_0-9]*(::[A-Za-z_][A-Za-z_0-9]*)*\z/;

# note: no method should die() because we are called by
# Perinci::Access::HTTP::Server without extra eval().

sub _init {
    require Class::Inspector;

    my ($self) = @_;

    # build a list of supported actions for each type of entity
    my %typeacts = (
        package  => [],
        function => [],
        variable => [],
    ); # key = type, val = [[ACTION, META], ...]

    # cache, so we can save a method call for every request()
    $self->{_actionmetas} = {}; # key = act

    my @comacts;
    for my $meth (@{Class::Inspector->methods(ref $self)}) {
        next unless $meth =~ /^actionmeta_(.+)/;
        my $act = $1;
        my $meta = $self->$meth();
        $self->{_actionmetas}{$act} = $meta;
        for my $type (@{$meta->{applies_to}}) {
            if ($type eq '*') {
                push @comacts, [$act, $meta];
            } else {
                push @{$typeacts{$type}}, [$act, $meta];
            }
        }
    }
    for my $type (keys %typeacts) {
        $typeacts{$type} = { map {$_->[0] => $_->[1]}
                                 @{$typeacts{$type}}, @comacts };
    }
    $self->{_typeacts} = \%typeacts;

    $self->{cache_size}            //= 100;
    $self->{use_tx}                //= 0;
    $self->{custom_tx_manager}     //= undef;
    $self->{load}                  //= 1;
    $self->{extra_wrapper_args}    //= {};
    $self->{extra_wrapper_convert} //= {};
    #$self->{use_wrapped_sub}
    #$self->{after_load}
    #$self->{prepend_namespace}
    #$self->{get_perl_package}
    #$self->{get_meta}
    #$self->{get_code}

    # to cache wrapped result
    if ($self->{cache_size}) {
        require Tie::Cache;
        tie my(%cache), 'Tie::Cache', $self->{cache_size};
        $self->{_cache} = \%cache;
    } else {
        $self->{_cache} = {};
    }
}

sub _get_code_and_meta {
    require Perinci::Sub::Wrapper;

    no strict 'refs';
    my ($self, $req) = @_;
    my $name = $req->{-perl_package} . "::" . $req->{-uri_leaf};
    return [200, "OK (cached)", $self->{_cache}{$name}]
        if $self->{_cache}{$name};

    no strict 'refs';
    my $metas = \%{"$req->{-perl_package}::SPEC"};
    my $meta = $metas->{ $req->{-uri_leaf} || ":package" };

    # supply a default, empty metadata for package, just so we can put $VERSION
    # into it
    if (!$meta && $req->{-type} eq 'package') {
        $meta = {v=>1.1};
    }
    return [404, "No metadata for $name"] unless $meta;

    my $code;
    my $extra;
    if ($req->{-type} eq 'function') {
        $code = \&{$name};
        my $wres = Perinci::Sub::Wrapper::wrap_sub(
            sub=>$code, sub_name=>$name, meta=>$meta,
            forbid_tags => ['die'],
            %{$self->{extra_wrapper_args}},
            convert=>{
                args_as=>'hash', result_naked=>0,
                %{$self->{extra_wrapper_convert}},
            });
        return [500, "Can't wrap function: $wres->[0] - $wres->[1]"]
            unless $wres->[0] == 200;
        if ($self->{use_wrapped_sub} //
                $meta->{"_perinci.access.inprocess.use_wrapped_sub"} // 1) {
            $code = $wres->[2]{sub};
        }

        $extra = {
            # store some info about the old meta, no need to store all for
            # efficiency
            orig_meta=>{
                result_naked=>$meta->{result_naked},
                args_as=>$meta->{args_as},
            },
        };
        $meta = $wres->[2]{meta};
        $self->{_cache}{$name} = [$code, $meta, $extra]
            if $self->{cache_size};
    }
    unless (defined $meta->{entity_version}) {
        my $ver = ${ $req->{-perl_package} . "::VERSION" };
        if (defined $ver) {
            $meta->{entity_version} = $ver;
        }
    }
    [200, "OK", [$code, $meta, $extra]];
}

sub get_perl_package {
    my $self = shift;
    return $self->{get_perl_package}->(@_) if $self->{get_perl_package};

    my ($req) = @_;

    my $path = $req->{uri}->path || "/";
    my ($dir, $leaf, $perl_package);
    if ($path eq '/') {
        $dir  = '/';
        $leaf = '';
    } else {
        if ($path =~ m!(.+)/+(.*)!) {
            $dir  = $1;
            $leaf = $2;
        } else {
            $dir  = $path;
            $leaf = '';
        }
        for ($perl_package) {
            $_ = $dir;
            s!^/+!!g;
            s!/+!::!g;
            $_ = "$self->{prepend_namespace}::$_" if $self->{prepend_namespace};
        }
    }

    return [400, "Invalid uri (translates to invalid Perl package ".
                '$perl_package']
        if $perl_package && $perl_package !~ $re_perl_package;

    $req->{-uri_dir}      = $dir;
    $req->{-uri_leaf}     = $leaf;
    $req->{-perl_package} = $perl_package;
    return;
}

sub _load_module {
    my ($self, $req) = @_;

    my $pkg = $req->{-perl_package};
    my $module_p = $pkg;
    $module_p =~ s!::!/!g;
    $module_p .= ".pm";

    # WISHLIST: cache negative result if someday necessary
    return if exists($INC{$module_p});

    eval { require $module_p };
    my $module_load_err = $@;
    return [500, "Can't load module $pkg: $module_load_err"]
        if $module_load_err &&
            !$self->{ignore_load_error} &&
            !$self->{_actionmetas}{$req->{action}}{module_missing_ok};

    if ($self->{after_load}) {
        eval { $self->{after_load}($self, module=>$pkg) };
        return [500, "after_load dies: $@"] if $@;
    }
}

sub get_meta {
    my $self = shift;
    return $self->{get_meta}->(@_) if $self->{get_meta};

    my ($req) = @_;
    my $res = $self->_get_code_and_meta($req);
    return $res unless $res->[0] == 200;
    $req->{-meta} = $res->[2][1];
    $req->{-orig_meta} = $res->[3]{orig_meta};
    return;
}

sub get_code {
    my $self = shift;
    return $self->{get_code}->(@_) if $self->{get_code};

    my ($req) = @_;
    my $res = $self->_get_code_and_meta($req);
    return $res unless $res->[0] == 200;
    $req->{-code} = $res->[2][0];
    return;
}

sub request {
    no strict 'refs';

    my ($self, $action, $uri, $extra) = @_;

    my $req = { action=>$action, %{$extra // {}} };
    my $res = $self->check_request($req);
    return $res if $res;

    my $am = $self->{_actionmetas}{$action};
    return [502, "Action '$action' not implemented"] unless $am;

    return [400, "Please specify URI"] unless $uri;
    $uri = URI->new($uri) unless blessed($uri);
    $req->{uri} = $uri;

    $res = $self->get_perl_package($req);
    return $res if $res;

    if ($self->{load} && $req->{-perl_package} &&
            !package_exists($req->{-perl_package})) {
        $res = $self->_load_module($req);
        return $res if $res;
    }

    my $type;
    my $entity_version;
    if (length($req->{-uri_leaf})) {
        if ($req->{-uri_leaf} =~ /^[%\@\$]/) {
            # XXX check existence of variable
            $type = 'variable';
        } else {
            return [404, "Can't find function $req->{-uri_leaf} ".
                        "in module $req->{-perl_package}"]
                unless defined &{"$req->{-perl_package}\::$req->{-uri_leaf}"};
            $type = 'function';
        }
    } else {
        $type = 'package';
        $entity_version = ${$req->{-perl_package} . '::VERSION'};
    }
    $req->{-type} = $type;
    $req->{-entity_version} = $entity_version;

    return [502, "Action '$action' not implemented for ".
                "'$req->{-type}' entity"]
        unless $self->{_typeacts}{ $type }{ $action };

    my $meth = "action_$action";
    # check transaction
    $self->$meth($req);
}

sub parse_url {
    my ($self, $uri) = @_;
    die "Please specify url" unless $uri;
    $uri = URI->new($uri) unless blessed($uri);
    {proto=>"pl", path=>$uri->path};
}

sub actionmeta_info { +{
    applies_to => ['*'],
    summary    => "Get general information on code entity",
    needs_meta => 0,
    needs_code => 0,
} }

sub action_info {
    my ($self, $req) = @_;
    my $res = {
        v    => 1.1,
        uri  => $req->{uri}->as_string,
        type => $req->{-type},
    };
    $res->{entity_version} = $req->{-entity_version}
        if defined $req->{-entity_version};
    [200, "OK", $res];
}

sub actionmeta_actions { +{
    applies_to => ['*'],
    summary    => "List available actions for code entity",
    needs_meta => 0,
    needs_code => 0,
} }

sub action_actions {
    my ($self, $req) = @_;
    my @res;
    for my $k (sort keys %{ $self->{_typeacts}{$req->{-type}} }) {
        my $v = $self->{_typeacts}{$req->{-type}}{$k};
        if ($req->{detail}) {
            push @res, {name=>$k, summary=>$v->{summary}};
        } else {
            push @res, $k;
        }
    }
    [200, "OK", \@res];
}

sub actionmeta_list { +{
    applies_to => ['package'],
    summary    => "List code entities inside this package code entity",

    # this action does not require the associated perl module to exist
    module_missing_ok => 1,
} }

sub action_list {
    require Module::List;

    my ($self, $req) = @_;
    my $detail = $req->{detail};
    my $f_type = $req->{type} || "";

    my @res;

    # XXX recursive?

    # get submodules
    unless ($f_type && $f_type ne 'package') {
        my $lres = Module::List::list_modules(
            $req->{-module} ? "$req->{-module}\::" : "",
            {list_modules=>1});
        my $p0 = $req->{-path};
        $p0 =~ s!/+$!!;
        for my $m (sort keys %$lres) {
            $m =~ s!.+::!!;
            my $uri = join("", "pl:", $p0, "/", $m, "/");
            if ($detail) {
                push @res, {uri=>$uri, type=>"package"};
            } else {
                push @res, $uri;
            }
        }
    }

    # get all entities from this module
    no strict 'refs';
    my $spec = \%{"$req->{-module}\::SPEC"};
    my $base = "pl:/$req->{-module}"; $base =~ s!::!/!g;
    for (sort keys %$spec) {
        next if /^:/;
        my $uri = join("", $base, "/", $_);
        my $t = $_ =~ /^[%\@\$]/ ? 'variable' : 'function';
        next if $f_type && $f_type ne $t;
        if ($detail) {
            push @res, {
                #v=>1.1,
                uri=>$uri, type=>$t,
            };
        } else {
            push @res, $uri;
        }
    }

    [200, "OK", \@res];
}

sub actionmeta_meta { +{
    applies_to => ['*'],
    summary    => "Get metadata",
} }

sub action_meta {
    my ($self, $req) = @_;
    return [404, "No metadata for /"] unless $req->{-perl_package};
    my $res = $self->get_meta($req);
    return $res if $res;
    [200, "OK", $req->{-meta}, {orig_meta=>$req->{-orig_meta}}];
}

sub actionmeta_call { +{
    applies_to => ['function'],
    summary    => "Call function",
} }

sub action_call {
    my ($self, $req) = @_;

    my $res;

    my $tm; # = does client mention tx_id?
    if (defined $req->{tx_id}) {
        $res = $self->_pre_tx_action($req);
        return $res if $res;
        $tm = $self->{_tx_manager};
        $tm->{_tx_id} = $req->{tx_id};
    }

    $res = $self->_get_code_and_meta($req);
    return $res unless $res->[0] == 200;
    my ($code, $meta) = @{$res->[2]};
    my %args = %{ $req->{args} // {} };

    my $risub = risub($meta);

    if ($req->{dry_run}) {
        return [412, "Function does not support dry run"]
            unless $risub->can_dry_run;
        if ($risub->feature('dry_run')) {
            $args{-dry_run} = 1;
        } else {
            $args{-dry_run} = 1;
            $args{-tx_action} = 'check_state';
            $args{-tx_action_id} = UUID::Random::generate();
            undef $tm;
        }
    }

    if ($risub->feature('progress')) {
        require Progress::Any;
        $args{-progress} = Progress::Any->get_indicator();
    }

    if ($tm) {
        $res = $tm->action(
            f => "$req->{-perl_package}::$req->{-uri_leaf}", args=>\%args,
            confirm => $req->{confirm},
        );
        $tm->{_tx_id} = undef if $tm;
    } else {
        $args{-confirm} = 1 if $req->{confirm};
        $res = $code->(%args);
    }

    $res;
}

sub actionmeta_complete_arg_val { +{
    applies_to => ['function'],
    summary    => "Complete function's argument value"
} }

sub action_complete_arg_val {
    my ($self, $req) = @_;
    my $arg = $req->{arg} or return [400, "Please specify arg"];
    my $word = $req->{word} // "";

    my $res = $self->_get_code_and_meta($req);
    return $res unless $res->[0] == 200;
    my (undef, $meta) = @{$res->[2]};
    my $args_p = $meta->{args} // {};
    my $arg_p = $args_p->{$arg} or return [400, "Unknown function arg '$arg'"];

    my $words;
    eval { # completion sub can die, etc.

        if ($arg_p->{completion}) {
            $words = $arg_p->{completion}(word=>$word);
            die "Completion sub does not return array"
                unless ref($words) eq 'ARRAY';
            return;
        }

        my $sch = $arg_p->{schema};

        my ($type, $cs) = @{$sch};
        if ($cs->{'in'}) {
            $words = $cs->{'in'};
            return;
        }

        if ($type =~ /^int\*?$/) {
            my $limit = 100;
            if ($cs->{between} &&
                    $cs->{between}[0] - $cs->{between}[0] <= $limit) {
                $words = [$cs->{between}[0] .. $cs->{between}[1]];
                return;
            } elsif ($cs->{xbetween} &&
                    $cs->{xbetween}[0] - $cs->{xbetween}[0] <= $limit) {
                $words = [$cs->{xbetween}[0]+1 .. $cs->{xbetween}[1]-1];
                return;
            } elsif (defined($cs->{min}) && defined($cs->{max}) &&
                         $cs->{max}-$cs->{min} <= $limit) {
                $words = [$cs->{min} .. $cs->{max}];
                return;
            } elsif (defined($cs->{min}) && defined($cs->{xmax}) &&
                         $cs->{xmax}-$cs->{min} <= $limit) {
                $words = [$cs->{min} .. $cs->{xmax}-1];
                return;
            } elsif (defined($cs->{xmin}) && defined($cs->{max}) &&
                         $cs->{max}-$cs->{xmin} <= $limit) {
                $words = [$cs->{xmin}+1 .. $cs->{max}];
                return;
            } elsif (defined($cs->{xmin}) && defined($cs->{xmax}) &&
                         $cs->{xmax}-$cs->{xmin} <= $limit) {
                $words = [$cs->{min}+1 .. $cs->{max}-1];
                return;
            }
        }

        $words = [];
    };
    return [500, "Completion died: $@"] if $@;

    [200, "OK", [grep /^\Q$word\E/, @$words]];
}

sub actionmeta_child_metas { +{
    applies_to => ['package'],
    summary    => "Get metadata of all child entities",
} }

sub action_child_metas {
    my ($self, $req) = @_;

    my $res = $self->action_list($req);
    return $res unless $res->[0] == 200;
    my $ents = $res->[2];

    my %res;
    my %om;
    for my $ent (@$ents) {
        $res = $self->request(meta => $ent);
        # ignore failed request
        next unless $res->[0] == 200;
        $res{$ent} = $res->[2];
        $om{$ent}  = $res->[3]{orig_meta};
    }
    [200, "OK", \%res, {orig_metas=>\%om}];
}

sub actionmeta_get { +{
    applies_to => ['variable'],
    summary    => "Get value of variable",
} }

sub action_get {
    no strict 'refs';

    my ($self, $req) = @_;
    local $req->{-leaf} = $req->{-leaf};

    # extract prefix
    $req->{-leaf} =~ s/^([%\@\$])//
        or return [500, "BUG: Unknown variable prefix"];
    my $prefix = $1;
    my $name = $req->{-perl_package} . "::" . $req->{-uri_leaf};
    my $res =
        $prefix eq '$' ? ${$name} :
            $prefix eq '@' ? \@{$name} :
                $prefix eq '%' ? \%{$name} :
                    undef;
    [200, "OK", $res];
}

sub _pre_tx_action {
    my ($self, $req) = @_;

    return [501, "Transaction not supported by server"]
        unless $self->{use_tx};

    # instantiate custom tx manager, per request if necessary
    if ((reftype($self->{custom_tx_manager}) // '') eq 'CODE') {
        eval {
            $self->{_tx_manager} = $self->{custom_tx_manager}->($self);
            die $self->{_tx_manager} unless blessed($self->{_tx_manager});
        };
        return [500, "Can't initialize custom tx manager: ".
                    "$self->{_tx_manager}: $@"] if $@;
    } elsif (!blessed($self->{_tx_manager})) {
        my $tm_cl = $self->{custom_tx_manager} // "Perinci::Tx::Manager";
        my $tm_cl_p = $tm_cl; $tm_cl_p =~ s!::!/!g; $tm_cl_p .= ".pm";
        eval {
            require $tm_cl_p;
            $self->{_tx_manager} = $tm_cl->new(pa => $self);
            die $self->{_tx_manager} unless blessed($self->{_tx_manager});
        };
        return [500, "Can't initialize tx manager ($tm_cl): $@"] if $@;
        # we just want to force newer version, we currently can't specify this
        # in Makefile.PL because peritm's tests use us. this might be rectified
        # in the future.
        if ($tm_cl eq 'Perinci::Tx::Manager') {
            $Perinci::Tx::Manager::VERSION >= 0.29
                or die "Your Perinci::Tx::Manager is too old, ".
                    "please install v0.29 or later";
        }
    }

    return;
}

sub actionmeta_begin_tx { +{
    applies_to => ['*'],
    summary    => "Start a new transaction",
} }

sub action_begin_tx {
    my ($self, $req) = @_;
    my $res = $self->_pre_tx_action($req);
    return $res if $res;

    $self->{_tx_manager}->begin(
        tx_id   => $req->{tx_id},
        summary => $req->{summary},
    );
}

sub actionmeta_commit_tx { +{
    applies_to => ['*'],
    summary    => "Commit a transaction",
} }

sub action_commit_tx {
    my ($self, $req) = @_;
    my $res = $self->_pre_tx_action($req);
    return $res if $res;

    $self->{_tx_manager}->commit(
        tx_id  => $req->{tx_id},
    );
}

sub actionmeta_savepoint_tx { +{
    applies_to => ['*'],
    summary    => "Create a savepoint in a transaction",
} }

sub action_savepoint_tx {
    my ($self, $req) = @_;
    my $res = $self->_pre_tx_action($req);
    return $res if $res;

    $self->{_tx_manager}->savepoint(
        tx_id => $req->{tx_id},
        sp    => $req->{tx_spid},
    );
}

sub actionmeta_release_tx_savepoint { +{
    applies_to => ['*'],
    summary    => "Release a transaction savepoint",
} }

sub action_release_tx_savepoint {
    my ($self, $req) =\ @_;
    my $res = $self->_pre_tx_action($req);
    return $res if $res;

    $self->{_tx_manager}->release_savepoint(
        tx_id => $req->{tx_id},
        sp    => $req->{tx_spid},
    );
}

sub actionmeta_rollback_tx { +{
    applies_to => ['*'],
    summary    => "Rollback a transaction (optionally to a savepoint)",
} }

sub action_rollback_tx {
    my ($self, $req) = @_;
    my $res = $self->_pre_tx_action($req);
    return $res if $res;

    $self->{_tx_manager}->rollback(
        tx_id => $req->{tx_id},
        sp    => $req->{tx_spid},
    );
}

sub actionmeta_list_txs { +{
    applies_to => ['*'],
    summary    => "List transactions",
} }

sub action_list_txs {
    my ($self, $req) = @_;
    my $res = $self->_pre_tx_action($req);
    return $res if $res;

    $self->{_tx_manager}->list(
        detail    => $req->{detail},
        tx_status => $req->{tx_status},
        tx_id     => $req->{tx_id},
    );
}

sub actionmeta_undo { +{
    applies_to => ['*'],
    summary    => "Undo a committed transaction",
} }

sub action_undo {
    my ($self, $req) = @_;
    my $res = $self->_pre_tx_action($req);
    return $res if $res;

    $self->{_tx_manager}->undo(
        tx_id   => $req->{tx_id},
        confirm => $req->{confirm},
    );
}

sub actionmeta_redo { +{
    applies_to => ['*'],
    summary    => "Redo an undone committed transaction",
} }

sub action_redo {
    my ($self, $req) = @_;
    my $res = $self->_pre_tx_action($req);
    return $res if $res;

    $self->{_tx_manager}->redo(
        tx_id   => $req->{tx_id},
        confirm => $req->{confirm},
    );
}

sub actionmeta_discard_tx { +{
    applies_to => ['*'],
    summary    => "Discard (forget) a committed transaction",
} }

sub action_discard_tx {
    my ($self, $req) = @_;
    my $res = $self->_pre_tx_action($req);
    return $res if $res;

    $self->{_tx_manager}->discard(
        tx_id => $req->{tx_id},
    );
}

sub actionmeta_discard_all_txs { +{
    applies_to => ['*'],
    summary    => "Discard (forget) all committed transactions",
} }

sub action_discard_all_txs {
    my ($self, $req) = @_;
    my $res = $self->_pre_tx_action($req);
    return $res if $res;

    $self->{_tx_manager}->discard_all(
        # XXX select client
    );
}

1;
# ABSTRACT: Use Rinci access protocol (Riap) to access Perl code

=for Pod::Coverage ^(actionmeta_.+|action_.+|get_(package|meta|code))$

=head1 SYNOPSIS

 # in Your/Module.pm

 package My::Module;
 our %SPEC;

 $SPEC{mult2} = {
     v => 1.1,
     summary => 'Multiple two numbers',
     args => {
         a => { schema=>'float*', req=>1, pos=>0 },
         b => { schema=>'float*', req=>1, pos=>1 },
     },
     examples => [
         {args=>{a=>2, b=>3}, result=>6},
     ],
 };
 sub mult2 {
     my %args = @_;
     [200, "OK", $args{a} * $args{b}];
 }

 $SPEC{multn} = {
     v => 1.1,
     summary => 'Multiple many numbers',
     args => {
         n => { schema=>[array=>{of=>'float*'}], req=>1, pos=>0, greedy=>1 },
     },
 };
 sub multn {
     my %args = @_;
     my @n = @{$args{n}};
     my $res = 0;
     if (@n) {
         $res = shift(@n);
         $res *= $_ while $_ = shift(@n);
     }
     return [200, "OK", $res];
 }

 1;

 # in another file

 use Perinci::Access::InProcess;
 my $pa = Perinci::Access::Process->new();

 # list all functions in package
 my $res = $pa->request(list => '/My/Module/', {type=>'function'});
 # -> [200, "OK", ['/My/Module/mult2', '/My/Module/multn']]

 # call function
 my $res = $pa->request(call => '/My/Module/mult2', {args=>{a=>2, b=>3}});
 # -> [200, "OK", 6]

 # get function metadata
 $res = $pa->request(meta => '/Foo/Bar/multn');
 # -> [200, "OK", {v=>1.1, summary=>'Multiple many numbers', ...}]


=head1 DESCRIPTION

This class implements Rinci access protocol (L<Riap>) to access local Perl code.
This might seem like a long-winded and slow way to access things that are
already accessible from Perl like functions and metadata (in C<%SPEC>). Indeed,
if you do not need Riap, you can access your module just like any normal Perl
module. But this class is designed to be flexible and allows you to customize
various aspects (most of the time, without subclassing).

=over 4

=item * Custom mapping from uri to package

By default, code entity's Riap URI maps directly to Perl packages, e.g.
C</Foo/Bar/> maps to Perl package C<Foo::Bar> while C</Foo/Bar/baz> maps to a
Perl function C<Foo::Bar::baz>.

You can override C<get_perl_package()> (either by subclassing or by supplying a
coderef to C<get_perl_package> attribute).

=item * Custom location of metadata

By default, metadata are stored embedded in Perl code in C<%SPEC> package
variables (with keys matching function names, or C<:package> for the package
metadata itself).

You can override C<get_meta()> (either by subclassing or by supplying a coderef
to C<get_meta> attribute). For example, you can store metadata in separate file
or database.

=item * Function wrapping

Wrapping is used to convert argument passing style, produce result envelope, add
argument validation, as well as numerous other functionalities. See
L<Perinci::Sub::Wrapper> for more details on wrapping. The default C<get_code>
behavior uses wrapping.

=item * Transaction/undo

This class implements L<Riap::Transaction>.

=back

Some other features that periai offers:

=over

=item * Progress indicator

Functions can express that they do progress updating through the C<features>
property in its metadata:

 features => {
     progress => 1,
     ...
 }

For these functions, periai will then pass a special argument C<-progress>
containing L<Progress::Any> object. Functions can update progress using this
object.

=back

=head2 How request is processed

User calls C<< $pa->request($action => $uri, \%extras) >>. Internally, the class
creates a hash C<$req> which contains Riap request keys as well as internal
information about the Riap request (the latter will be prefixed with dash C<->).
Initially it will contain C<action> and C<uri> (converted to L<URI> object) and
the C<%extras> keys from the request() arguments sent by the user.

C<get_perl_package()> will be called, with C<$req> as argument. It is expected
to set package name C<< $req->{-perl_package} >> containing Perl package name,
C<< $res->{-uri_dir} >> containing the "dir" part of the uri and C<<
$res->{-uri_leaf} >> containing the "basename" part of the uri. It should return
false on success, or an envelope response on error (where processing will stop
with this response).

For example, if uri is C</Foo/Bar/> then C<-uri_dir> is C</Foo/Bar/> and
C<-uri_leaf> is an empty string. If uri is C</Foo/Bar/baz> then C<-uri_dir> is
C</Foo/Bar/> while C<-uri_leaf> is C<baz>. C<-uri_dir> will be used for the
C<list> action.

Depending on the C<load> setting, the Perl module at C<< $req->{-perl_package}
>> will be require'd if it has not been loaded. If loading is successful and the
C<after_load> setting is set, the hook will be called. If loading fails,
processing will stop with an error response, unless for actions which does not
require the Perl package (like C<action>) or when C<ignore_load_error> is set to
true.

The code entity type is then determined currently using a few simple heuristic
rules: if C<-uri_leaf> is empty string, type is C<package>. If C<-uri_leaf>
begins with C<[$%@]>, type is C<variable>. Otherwise, type is C<function>.

Then the appropriate C<action_ACTION()> method will be called. For example if
action is C<meta> then C<action_meta()> method will be called, with C<$req> as
the argument. This will in turn, depending on the action, either call
C<get_meta()> (for example if action is C<meta>) or C<get_code()> (for example
if action is C<call>), also with C<$req> as the argument. C<get_meta()> and
C<get_code()> should return nothing on success, and set either C<< $req->{-meta}
>> (a defhash containing Rinci metadata) or C<< $req->{-code} >> (a coderef)
respectively. On error, they must return an enveloped response.


=head1 METHODS

=head2 PKG->new(%attrs) => OBJ

Instantiate object. Known attributes:

=over 4

=item * prepend_namespace => STR

If specified, will prepend this to Perl package names translated from uri Riap
request key. For example, normally C</Foo/Bar/> maps to Perl package
C<Foo::Bar>. But if C<prepend_namespace> is set to C<MyCompany::MyProduct>, then
C</Foo/Bar/> will map to Perl package C<MyCompany::MyProduct::Foo::Bar>.

This setting is only relevant if you use the default C<get_package>.

=item * load => BOOL (default: 1)

Whether to load Perl modules that are requested. For example, a request to
C</Foo/Bar/> will, under the default C<get_package> behavior, map to Perl
package C<Foo::Bar>. If this setting is on, the Perl module C<Foo::Bar> will be
attempted to be loaded.

=item * ignore_load_error => BOOL (default: 0)

If set to true, failure loading Perl module will not abort the request.

=item * after_load => CODE

If set, code will be executed the first time Perl module is successfully loaded.

This is only relevant if you use the default C<get_package> behavior.

=item * use_wrapped_sub => BOOL (default: 1)

If set to false, then wil use original subroutine instead of wrapped one, for
example if you are very concerned about performance (do not want to add another
eval {} and subroutine call introduced by wrapping) or do not need the
functionality provided by the wrapper (e.g. your function does not die and
already validates its arguments, etc).

Can also be set on a per-entity basis by setting the
C<_perinci.access.inprocess.use_wrapped_sub> metadata property.

This is only relevant if you use the default C<get_code> behavior.

=item * cache_size => INT (default: 100)

Specify cache size (in number of items). Cache saves the result of function
wrapping so future requests to the same function need not involve wrapping
again. Setting this to 0 disables caching.

This is only relevant if you enable wrapping and only if you use the default
C<get_code> behavior.

=item * extra_wrapper_args => HASH

If set, will be passed to L<Perinci::Sub::Wrapper>'s wrap_sub() when wrapping
subroutines. Some applications of this include: adding C<timeout> or
C<result_postfilter> properties to functions.

This is only relevant if you use the default C<get_meta> and C<get_code>
behavior.

=item * extra_wrapper_convert => HASH

If set, will be passed to L<Perinci::Sub::Wrapper> wrap_sub()'s C<convert>
argument when wrapping subroutines. Some applications of this include: changing
C<default_lang> of metadata.

This is only relevant if you use the default C<get_meta> and C<get_code>
behavior.

=item * use_tx => BOOL (default 0)

Whether to allow transaction requests from client. Since this can cause the
server to store transaction/undo data, this must be explicitly allowed.

You need to install L<Perinci::Tx::Manager> for transaction support (unless you
are using another transaction manager).

=item * custom_tx_manager => STR|CODE

Can be set to a string (class name) or a code that is expected to return a
transaction manager class.

By default, L<Perinci::Tx::Manager> is instantiated and maintained (not
reinstantiated on every request), but if C<custom_tx_manager> is a coderef, it
will be called on each request to get transaction manager. This can be used to
instantiate Perinci::Tx::Manager in a custom way, e.g. specifying per-user
transaction data directory and limits, which needs to be done on a per-request
basis.

=back

=head2 $pa->request($action => $server_url, \%extra) => $res

Process Riap request and return enveloped result. $server_url will be used as
the Riap request key 'uri', as there is no server in this case.

Some notes:

=over 4

=item * Metadata returned by the 'meta' action has normalized schemas in them

Schemas in metadata (like in the C<args> and C<return> property) are normalized
by L<Perinci::Sub::Wrapper>.

=back

=head2 $pa->parse_url($server_url) => HASH


=head1 FAQ

=head2 Why wrap?

The wrapping process accomplishes several things, among others: checking of
metadata, normalization of schemas in metadata, also argument validation and
exception trapping in function.

The function wrapping introduces a small overhead when performing a sub call
(typically around several to tens of microseconds on an Intel Core i5 1.7GHz
notebook). This is usually smaller than the overhead of
Perinci::Access::InProcess itself (typically in the range of 100 microseconds).
But if you are concerned about the wrapping overhead, see the C<use_wrapped_sub>
option.


=head2 Why %SPEC?

The name was first chosen when during Sub::Spec era, so it stuck.


=head1 SEE ALSO

L<Riap>, L<Rinci>

=cut
