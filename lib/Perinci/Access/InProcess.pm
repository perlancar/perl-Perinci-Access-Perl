package Perinci::Access::InProcess;

use 5.010001;
use strict;
use warnings;
use Log::Any '$log';

use parent qw(Perinci::Access::Base);

use Perinci::Object;
use Scalar::Util qw(blessed reftype);
use SHARYANTO::ModuleOrPrefix::Path qw(module_or_prefix_path);
use SHARYANTO::Package::Util qw(package_exists);
use Tie::Cache;
use URI;

# VERSION

our $re_perl_package =
    qr/\A[A-Za-z_][A-Za-z_0-9]*(::[A-Za-z_][A-Za-z_0-9]*)*\z/;

# note: no method should die() because we are called by
# Perinci::Access::HTTP::Server without extra eval().

sub new {
    require Class::Inspector;

    my $class = shift;
    my $self = $class->SUPER::new(@_);

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
    $self->{wrap}                  //= 1;
    $self->{custom_tx_manager}     //= undef;
    $self->{load}                  //= 1;
    $self->{extra_wrapper_args}    //= {};
    $self->{extra_wrapper_convert} //= {};
    #$self->{after_load}
    #$self->{allow_paths}
    #$self->{deny_paths}

    # convert {allow,deny}_paths to array of regex to avoid reconstructing regex
    # on each request
    for my $pp ($self->{allow_paths}, $self->{deny_paths}) {
        next unless defined $pp;
        $pp = [$pp] unless ref($pp) eq 'ARRAY';
        for (@$pp) {
            $_ = qr#\A\Q$_\E(?:/|\z)# unless ref($_) eq 'Regexp';
        }
    }

    # to cache wrapped result
    if ($self->{cache_size}) {
        tie my(%cache), 'Tie::Cache', $self->{cache_size};
        $self->{_cache} = \%cache;
    } else {
        $self->{_cache} = {};
    }

    $self;
}

# for older Perinci::Access::Base 0.28-, to remove later
sub _init {}

sub __match_path {
    my ($path, $paths) = @_;

    for my $p (@$paths) {
        return 1 if $path =~ $p;
    }
    0;
}

sub _parse_uri {
    my ($self, $req) = @_;

    my $path = $req->{uri}->path || "/";

    # TODO: do some normalization on paths, allow this to be optional if eats
    # too much cycles

    if (defined($self->{allow_paths}) &&
            !__match_path($path, $self->{allow_paths})) {
        return [403, "Forbidden uri path (does not match allow_paths)"];
    }
    if (defined($self->{deny_paths}) &&
            __match_path($path, $self->{deny_paths})) {
        return [403, "Forbidden uri path (matches deny_paths)"];
    }

    my ($dir, $leaf, $perl_package);
    if ($path =~ m!\A/(.+)/+(.*)\z!) {
        $dir  = $1;
        $leaf = $2;
    } elsif ($path =~ m!\A/+(.+)\z!) {
        $dir  = '/';
        $leaf = $1;
    } else {
        $dir = '/';
        $leaf = '';
    }
    for ($perl_package) {
        $_ = $dir;
        s!\A/+!!;
        s!/+!::!g;
    }
    return [400, "Invalid uri"]
        if $perl_package && $perl_package !~ $re_perl_package;

    my $type;
    if (length $leaf) {
        if ($leaf =~ /^[%\@\$]/) {
            $type = 'variable';
        } else {
            $type = 'function';
        }
    } else {
        $type = 'package';
    }

    $req->{-uri_path}     = $path;
    $req->{-uri_dir}      = $dir;
    $req->{-uri_leaf}     = $leaf;
    $req->{-perl_package} = $perl_package;
    $req->{-type}         = $type;

    return;
}

# key = module_p, val = error resp or undef if successful
my %loadcache;
tie %loadcache, 'Tie::Cache', 200;

sub _load_module {
    my ($self, $req) = @_;

    my $pkg = $req->{-perl_package};

    # there is no module to load, or we are instructed not to load any modules.
    return if !$pkg || !$self->{load};

    my $module_p = $pkg;
    $module_p =~ s!::!/!g;
    $module_p .= ".pm";

    # module has been required before and successfully loaded
    return if $INC{$module_p};

    # module has been required before and failed
    return [500, "Module $pkg has failed to load previously"]
        if exists($INC{$module_p});

    # use cache result (for caching errors, or packages like 'main' and 'CORE'
    # where no modules for such packages exist)
    return $loadcache{$module_p} if exists $loadcache{$module_p};

    # load and cache negative result
    my $res;
    {
        my $fullpath = module_or_prefix_path($module_p);

        # when the module path does not exist, but the package does, we can
        # ignore this error. for example: main, CORE, etc.
        my $pkg_exists = package_exists($pkg);

        if (!$fullpath) {
            last if $pkg_exists;
            $res = [404, "Can't find module or prefix path for package $pkg"];
            last;
        } elsif ($fullpath !~ /\.pm$/) {
            last if $pkg_exists;
            $res = [405, "Can only find a prefix path for package $pkg"];
            last;
        }
        eval { require $module_p };
        if ($@) {
            $res = [500, "Can't load module $pkg (probably compile error): $@"];
            last;
        }
        # load is successful
        if ($self->{after_load}) {
            eval { $self->{after_load}($self, module=>$pkg) };
            $log->error("after_load for package $pkg dies: $@") if $@;
        }
    }
    $loadcache{$module_p} = $res;
    return $res;
}

sub _get_code_and_meta {
    require Perinci::Sub::Wrapper;

    no strict 'refs';
    my ($self, $req) = @_;
    my $name = $req->{-perl_package} . "::" . $req->{-uri_leaf};
    my $type = $req->{-type};
    return [200, "OK (cached)", $self->{_cache}{$name}]
        if $self->{_cache}{$name};

    my $res = $self->_load_module($req);
    # missing module (but existing prefix) is okay for package, we construct an
    # empty package metadata for it
    return $res if $res && !($type eq 'package' && $res->[0] == 405);

    no strict 'refs';
    my $metas = \%{"$req->{-perl_package}::SPEC"};
    my $meta = $metas->{ $req->{-uri_leaf} || ":package" };

    if (!$meta && $type eq 'package') {
        $meta = {v=>1.1};
    }

    return [404, "No metadata for $name"] unless $meta;

    my $code;
    my $extra = {};
    if ($req->{-type} eq 'function') {
        $code = \&{$name};
        return [404, "Can't find function $req->{-uri_leaf} in ".
                    "module $req->{-perl_package}"]
            unless defined &{$name};
        if ($self->{wrap}) {
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
            $code = $wres->[2]{sub};
            $extra->{orig_meta} = {
                # store some info about the old meta, no need to store all for
                # efficiency
                result_naked=>$meta->{result_naked},
                args_as=>$meta->{args_as},
            };
            $meta = $wres->[2]{meta};
        }
        $self->{_cache}{$name} = [$code, $meta, $extra]
            if $self->{cache_size};
    }
    unless (defined $meta->{entity_v}) {
        my $ver = ${ $req->{-perl_package} . "::VERSION" };
        if (defined $ver) {
            $meta->{entity_v} = $ver;
        }
    }
    [200, "OK", [$code, $meta, $extra]];
}

sub get_meta {
    my $self = shift;

    my ($req) = @_;

    if (!$req->{-perl_package}) {
        $req->{-meta} = {v=>1.1}; # empty metadata for /
        return;
    }

    my $res = $self->_get_code_and_meta($req);
    if ($res->[0] == 405) {
        $req->{-meta} = {v=>1.1}; # empty package metadata for dir
        return;
    } elsif ($res->[0] != 200) {
        return $res;
    }
    $req->{-meta} = $res->[2][1];
    $req->{-orig_meta} = $res->[3]{orig_meta};
    return;
}

sub get_code {
    my $self = shift;

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

    $res = $self->_parse_uri($req);
    return $res if $res;

    return [502, "Action '$action' not implemented for ".
                "'$req->{-type}' entity"]
        unless $self->{_typeacts}{ $req->{-type} }{ $action };

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

    my $mres = $self->get_meta($req);
    return $mres if $mres;

    my $res = {
        v    => 1.1,
        uri  => $req->{uri}->as_string,
        type => $req->{-type},
    };

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

    my $mres = $self->get_meta($req);
    return $mres if $mres;

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
} }

sub action_list {
    require Module::List;

    my ($self, $req) = @_;
    my $detail = $req->{detail};
    my $f_type = $req->{type} || "";

    my @res;

    my $filter_path = sub {
        my $path = shift;
        if (defined($self->{allow_paths}) &&
                !__match_path($path, $self->{allow_paths})) {
            return 0;
        }
        if (defined($self->{deny_paths}) &&
                __match_path($path, $self->{deny_paths})) {
            return 0;
        }
        1;
    };

    # TODO: if load=0, then instead of using list_modules(), use list_packages()
    # instead and skip the filesystem.

    # get submodules
    unless ($f_type && $f_type ne 'package') {
        my $lres = Module::List::list_modules(
            $req->{-perl_package} ? "$req->{-perl_package}\::" : "",
            {list_modules=>1, list_prefixes=>1});
        my $p0 = $req->{-uri_path};
        $p0 =~ s!/+$!!;
        my %mem;
        for my $m (sort keys %$lres) {
            $m =~ s!::$!!;
            $m =~ s!.+::!!;
            my $path = join("", $p0, "/", $m, "/");
            next unless $filter_path->($path);
            my $uri = "pl:$path";
            next if $mem{$uri}++;
            if ($detail) {
                push @res, {uri=>$uri, type=>"package"};
            } else {
                push @res, $uri;
            }
        }
    }

    my $res = $self->_load_module($req);
    return $res if $res && $res->[0] != 405;

    # get all entities from this module
    no strict 'refs';
    my $spec = \%{"$req->{-perl_package}\::SPEC"};
    my $base = $req->{-uri_path};
    for (sort keys %$spec) {
        next if /^:/;
        my $path = join("", $base, $_);
        next unless $filter_path->($path);
        my $uri = "pl:$path";
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

    my $res = $self->get_meta($req);
    return $res if $res;

    [200, "OK", $req->{-meta}, {orig_meta=>$req->{-orig_meta}}];
}

sub actionmeta_call { +{
    applies_to => ['function'],
    summary    => "Call function",
} }

sub action_call {
    require UUID::Random;

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
        if ($cs->{in}) {
            $words = $cs->{in};
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
    local $req->{-uri_leaf} = $req->{-uri_leaf};

    # extract prefix
    $req->{-uri_leaf} =~ s/^([%\@\$])//
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

=for Pod::Coverage ^(actionmeta_.+|action_.+|get_(meta|code))$

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
 # -> [200, "OK", ['pl:/My/Module/mult2', 'pl:/My/Module/multn']]

 # call function
 my $res = $pa->request(call => 'pl:/My/Module/mult2', {args=>{a=>2, b=>3}});
 # -> [200, "OK", 6]

 # get function metadata
 $res = $pa->request(meta => '/Foo/Bar/multn');
 # -> [200, "OK", {v=>1.1, summary=>'Multiple many numbers', ...}]


=head1 DESCRIPTION

This class implements Rinci access protocol (L<Riap>) to access local Perl code.
This might seem like a long-winded and slow way to access things that are
already accessible from Perl like functions and metadata (in C<%SPEC>). Indeed,
if you do not need Riap, you can access your module just like any normal Perl
module.

Supported features:

=over

=item * Basic Riap actions

These include C<info>, C<actions>, C<meta>, C<list>, and C<call> actions.

=item * Transaction/undo

According to L<Rinci::Transaction>.

=item * Function wrapping

Wrapping is used to convert argument passing style, produce result envelope, add
argument validation, as well as numerous other functionalities. See
L<Perinci::Sub::Wrapper> for more details on wrapping. The default behavior will
call wrapped functions.

=item * Custom location of metadata

By default, metadata are assumed to be stored embedded in Perl source code in
C<%SPEC> package variables (with keys matching function names, C<$variable>
names, or C<:package> for the package metadata itself).

You can override C<get_meta()> to provide custom behavior. For example, you can
store metadata in separate file or database.

=item * Custom code entity tree

By default, tree are formed by traversing Perl packages and their contents, for
example if a C<list> action is requested on uri C</Foo/Bar/> then the contents
of package C<Foo::Bar> and its subpackages will be traversed for the entities.

You can override C<action_list()> to provide custom behavior. For example, you
can lookup from the database.

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

User calls C<< $pa->request($action => $uri, \%extras) >>. Internally, the
method creates a hash C<$req> which contains Riap request keys as well as
internal information about the Riap request (the latter will be prefixed with
dash C<->). Initially it will contain C<action> and C<uri> (converted to L<URI>
object) and the C<%extras> keys from the request() arguments sent by the user.

Internal C<_parse_uri()> method will be called to parse C<uri> into C<-uri_dir>
(the "dir" part), C<-uri_leaf> (the "basename" part), and C<-perl_package>.
Forbidden or invalid paths will cause this method to return an enveloped error
response and the request to stop. For example, if C<uri> is C</Foo/Bar/> then
C<-uri_dir> is C</Foo/Bar/> and C<-uri_leaf> is an empty string. If C<uri> is
C</Foo/Bar/baz> then C<-uri_dir> is C</Foo/Bar/> while C<-uri_leaf> is C<baz>.
C<-uri_dir> will be used for the C<list> action. In both cases, C<-perl_package>
will be set to C<Foo::Bar>.

The code entity type is then determined currently using a few simple heuristic
rules: if C<-uri_leaf> is empty string, type is C<package>. If C<-uri_leaf>
begins with C<[$%@]>, type is C<variable>. Otherwise, type is C<function>.
C<-type> will be set.

After this, the appropriate C<action_ACTION()> method will be called. For
example if action is C<meta> then C<action_meta()> method will be called, with
C<$req> as the argument. This will in turn, depending on the action, either call
C<get_meta()> (for example if action is C<meta>) or C<get_code()> (for example
if action is C<call>), also with C<$req> as the argument. C<get_meta()> and
C<get_code()> should return nothing on success, and set either C<-meta> (a
defhash containing Rinci metadata) or C<-code> (a coderef), respectively. On
error, they must return an enveloped error response.

C<get_meta()> or C<get_code()> might call C<_load_module()> to load Perl modules
if the C<load> attribute is set to true.


=head1 METHODS

=head2 PKG->new(%attrs) => OBJ

Instantiate object. Known attributes:

=over 4

=item * load => BOOL (default: 1)

Whether to load Perl modules that are requested.

=item * after_load => CODE

If set, code will be executed the first time Perl module is successfully loaded.

=item * wrap => BOOL (default: 1)

If set to false, then wil use original subroutine and metadata instead of
wrapped ones, for example if you are very concerned about performance (do not
want to add another eval {} and subroutine call introduced by wrapping) or do
not need the functionality provided by the wrapper (e.g. your function does not
die and already validates its arguments, you do not want Sah schemas in the
metadata to be normalized, etc).

Wrapping is implemented inside C<get_meta()> and C<get_code()>.

=item * extra_wrapper_args => HASH

If set, will be passed to L<Perinci::Sub::Wrapper>'s wrap_sub() when wrapping
subroutines. Some applications of this include: adding C<timeout> or
C<result_postfilter> properties to functions.

This is only relevant if you enable C<wrap>.

=item * extra_wrapper_convert => HASH

If set, will be passed to L<Perinci::Sub::Wrapper> wrap_sub()'s C<convert>
argument when wrapping subroutines. Some applications of this include: changing
C<default_lang> of metadata.

This is only relevant if you enable C<wrap>.

=item * cache_size => INT (default: 100)

Specify cache size (in number of items). Cache saves the result of function
wrapping so future requests to the same function need not involve wrapping
again. Setting this to 0 disables caching.

Caching is implemented inside C<get_meta()> and C<get_code()> so you might want
to implement your own caching if you override those.

=item * allow_paths => REGEX|STR|ARRAY

If defined, only requests with C<uri> matching specified path will be allowed.
Can be a string (e.g. C</spanel/api/>) or regex (e.g. C<< qr{^/[^/]+/api/} >>)
or an array of those.

=item * deny_paths => REGEX|STR|ARRAY

If defined, requests with C<uri> matching specified path will be denied. Like
C<allow_paths>, value can be a string (e.g. C</spanel/api/>) or regex (e.g. C<<
qr{^/[^/]+/api/} >>) or an array of those.

=item * use_tx => BOOL (default: 0)

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
