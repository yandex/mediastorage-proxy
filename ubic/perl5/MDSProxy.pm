package Ubic::Service::MDSProxy;

use strict;
use warnings;

use Ubic::Daemon qw(:all);

use Ubic::Result qw(result);

###use Ubic::Service::Shared::Ulimits;
use Ubic::Service::Shared::Dirs;

use parent qw(Ubic::Service::SimpleDaemon);

use Params::Validate qw(:all);

use LogGiver::common;
use FCGI::Client;
use IO::Socket::UNIX;

my %opt2arg = ();
for my $arg (qw(configuration server:announce server:announce-interval))
{
    my $opt = $arg;
    $opt2arg{$opt} = $arg;
}

use vars qw($params);

sub new {
    my $class = shift;

    $params = validate(@_, {
        user => { type => SCALAR, default => "root", optional => 1 },
        log_dir => { type => SCALAR, default => "/var/log/mdst", optional => 1 },
        run_dir => { type => SCALAR, default => "/var/run/mediastorage", optional => 1 },
        rlimit_nofile => { type => SCALAR,
                           regex => qr/^\d+$/,
                           optional => 1,
                        },
        rlimit_core => {   type => SCALAR,
                           regex => qr/^\-?\d+$/,
                           optional => 1 },
        rlimit_stack => {  type => SCALAR,
                           regex => qr/^\d+$/,
                           optional => 1  },
    });

    #
    # check ulimits
    #
    my $ulimits;
    if (defined $params->{rlimit_nofile}) { $ulimits->{"RLIMIT_NOFILE"} = $params->{rlimit_nofile} };
    if (defined $params->{rlimit_core})   { $ulimits->{"RLIMIT_CORE"} = $params->{rlimit_core} };
    if (defined $params->{rlimit_stack})  { $ulimits->{"RLIMIT_STACK"} = $params->{rlimit_stack} };

    my $bin = [
        '/usr/bin/mediastorage-proxy -c /etc/elliptics/mediastorage-proxy.conf'
    ];

    my $daemon_user = $params->{user};
    return $class->SUPER::new({
        bin => $bin,
        user => 'root',
        ulimit => $ulimits || {},
        daemon_user => $daemon_user,
        ubic_log => $params->{log_dir}.'/ubic.log',
        stdout => $params->{log_dir}.'/stdout.log',
        stderr => $params->{log_dir}.'/stderr.log',
        auto_start => 1,
    });
}

sub start_impl {
    my $self = shift;

    Ubic::Service::Shared::Dirs::directory_checker( $params->{log_dir}, $params->{user});
    Ubic::Service::Shared::Dirs::directory_checker( $params->{run_dir}, $params->{user});

    $self->SUPER::start_impl(@_);
}


sub status_impl {
    my $self = shift;
    my $status = $self->SUPER::status_impl();

    return $status if $status->status ne 'running';

    LogGiver::common::define_vars();
    my $stdout;
    eval{
        my $socket_file = LogGiver::common::get_config_value('fcgi_socket');
        my $sock=IO::Socket::UNIX->new( Peer=>$socket_file );
        my $client = FCGI::Client::Connection->new( sock => $sock );
        my $stderr;
        ($stdout,$stderr) = $client->request(
{
    REQUEST_METHOD => 'GET',
    SCRIPT_NAME    => '/ping',
#    SERVER_PORT    => 3132,
},'');
    };
    ###print "stdout: $stdout\n";
    if ( !defined $stdout || (defined $stdout && $stdout !~ /200 ok$/) ) { 
        ###return result("broken", "fastcgi return status '$stdout'");
        return result("broken", "fastcgi didn't return 200");
    };

    return "running";
}

sub timeout_options {
    my $self = shift;
    { start => { step => 1, trials => 10 } };
}

sub reload {
    my ( $self ) = @_;
    my $status = check_daemon($self->pidfile) or die result('not running');
    kill HUP => $status->pid;

    return 'reloaded';
}

1;
