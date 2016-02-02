#!/usr/bin/env perl

use 5.020;
use warnings;

use Carp;
use DBI;
use JSON;
use Socket;
use Net::Ping;
use Net::DNS::Resolver;
use Net::XMPP;
use Net::SSH2;
use LWP::UserAgent;
use IPC::ConcurrencyLimit;
use DateTime;

#use Data::Printer;

local $0 = "iMon";

my $config_file = 'conf.pl';
my $conf;
get_config( $config_file );

# Try to get the run lock, else exit.
#
# There can be only one.
my $limit = IPC::ConcurrencyLimit->new(
    type        => 'Flock',
    max_procs   => 1,
    path        => $ENV{HOME} . '/tmp',
);
my $lock_id = $limit->get_lock;
unless ( $lock_id ) {
    say "Another process is running" if $conf->{'debug'};
    exit(0);
}

my $dt = DateTime->now(
        time_zone => 'Europe/Rome',
);

my $dbh = DBI->connect(
    "dbi:Pg:dbname=" . $conf->{'dbName'} . ";host=" . $conf->{'dbHost'} . ";port=" . $conf->{'dbPort'},
    $conf->{'dbUser'},
    $conf->{'dbPass'}
) or croak $!;

# Get all servers to be checked
my $serverQuery = "SELECT name,ip,services,hostname FROM server WHERE \"check\" = true";
my $sth = $dbh->prepare($serverQuery);
$sth->execute or croak $dbh->errstr;

# Check all servers for available services

while ( my $server = $sth->fetchrow_hashref() ) {
    my $srv = {
        name    => $server->{'name'},
        ip      => $server->{'ip'},
        hostname => $server->{'hostname'},
        status  => "OK",
        up      => 1,
    };
    my $services = decode_json $server->{'services'};

    $srv->{'port'} = $services->{'http'}    and Log ( CheckHTTP     ( $srv ) );
    $srv->{'port'} = $services->{'ftp'}     and Log ( CheckFTP      ( $srv ) );
    $srv->{'port'} = $services->{'ssh'}     and Log ( CheckSSH      ( $srv ) );
    $srv->{'port'} = $services->{'xmmp'}    and Log ( CheckXMPP     ( $srv ) );
    $srv->{'port'} = $services->{'imap4s'}  and Log ( CheckIMAP4s   ( $srv ) );
    $srv->{'port'} = $services->{'pop3s'}   and Log ( CheckPOP3s    ( $srv ) );
    $srv->{'port'} = $services->{'dns'}     and Log ( CheckDNS      ( $srv ) );
    if( ( $dt->minute == 0 or $dt->minute == 1 ) and $dt->hour % 2 ) { # Only check every odd hour
        $services->{'spam'}                 and Log ( CheckSpam     ( $srv ) );
    }
}

# Checks
sub CheckTCP {
    my $srv = shift;
    # Assume service is up
    $srv->{'up'} = 1;

    # Check if port is reachable (just connect and disconnect, no data exchange)
    my $p = Net::Ping->new( "tcp", $conf->{'defaultTimeout'} );
    $p->port_number( $srv->{'port'} );
    unless ( $p->ping( $srv->{'ip'} ) ) {
        $srv->{'up'} = 0;
        $srv->{'status'} = "TCP Ping failed on port $srv->{'port'}";
    }

    return ( $srv );
}

sub CheckHTTP {
    my $srv = shift;

    # If port is unreachable, stop here.
    $srv = CheckTCP ( $srv );
    return ( "http", $srv ) unless $srv->{'up'};

    # Make a valid request
    my $ua = LWP::UserAgent->new;
    $ua->agent ( "iMon/1.0 " );
    $ua->timeout ( $conf->{'defaultTimeout'} );
    my $host;
    $host = $srv->{'ip'};
    $host = $srv->{'hostname'} if $srv->{'ip'} =~ "0\.0\.0\.0";

#    p $srv->{'name'} . "\t" . "http://" . $host . ":" . $srv->{'port'} . "/robots.txt";

    require HTTP::Headers;
    my $h = HTTP::Headers->new;
    $h->header('host' => $host);

    my $req = HTTP::Request->new ( GET => "http://" . $host . ":" . $srv->{'port'} . "/robots.txt", $h );
    my $res = $ua->request ( $req );

    # Consider 404 responses as success
    if ( !$res->is_success && $res->status_line ne "404 Not Found" ) {
        $srv->{'up'} = 0;
        $srv->{'status'} = $res->status_line;
    }

    return ( "http", $srv );
}

sub CheckFTP {
    my $srv = shift;

    # If port is unreachable, stop here.
    $srv = CheckTCP ( $srv );
    return ( "ftp", $srv ) unless $srv->{'up'};

    # TODO: Make an FTP connection

    return ( "ftp", $srv );
}

sub CheckSSH {
    my $srv = shift;

    # If port is unreachable, stop here.
    $srv = CheckTCP ( $srv );
    return ( "ssh", $srv ) unless $srv->{'up'};

    my $ssh2 = Net::SSH2->new();
    $ssh2->connect($srv->{'ip'}, $srv->{'port'}, Timeout => $conf->{'defaultTimeout'}) or $srv->{'up'} = 0;
    my ($err_code, $err_name, $err_string) = $ssh2->error();
    $srv->{'status'} = $err_code . ': ' . $err_name . ' - ' . $err_string;
    $ssh2->disconnect;

    return ( "ssh", $srv );
}

sub CheckXMPP {
    my $srv = shift;

    # If port is unreachable, stop here.
    $srv = CheckTCP ( $srv );
    return ( "xmmp", $srv ) unless $srv->{'up'};

    # TODO: Make an XMPP connection

    return ( "xmmp", $srv );
}

sub CheckIMAP4s {
    my $srv = shift;

    # If port is unreachable, stop here.
    $srv = CheckTCP ( $srv );
    return ( "imap4s", $srv ) unless $srv->{'up'};

    # TODO: Make an imap4s connection
    return ( "imap4s", $srv );
}

sub CheckPOP3s {
    my $srv = shift;

    # If port is unreachable, stop here.
    $srv = CheckTCP ( $srv );
    return ( "pop3s", $srv ) unless $srv->{'up'};

    # TODO: Make a pop3s connection
    return ( "pop3s", $srv );
}


sub CheckDNS {
    my $srv = shift;

    my $res = Net::DNS::Resolver->new (
        nameservers => [ $srv->{'ip'} ],
        recurse     => 0,
    );

    unless ( my $answer = $res->query( 'unbit.it', 'A' ) ) {
        $srv->{'up'} = 0;
        $srv->{'status'} = $res->string;
    }

    return ( "dns", $srv );
}

sub CheckSpam {
    my $srv = shift;

    $srv->{'ip'} =~ m/(\d+)\.(\d+)\.(\d+)\.(\d+)/x;
    my $rev_ip;
    if( defined $1 and defined $2 and defined $3 and defined $4 ) {
        $rev_ip = $4 . '.' . $3 . '.' . $2 . '.' . $1;
    } else {
        croak "Not an ip: " . $srv->{'ip'};
    }

    my $res = Net::DNS::Resolver->new (
        nameservers => [ "8.8.8.8" ],
        recurse     => 1,
    );

    # Spamcop
    if ( my $answer = $res->query( $srv->{'ip'} . '.bl.spamcop.net.', 'A' ) ) {
        $srv->{'up'} = 0;
        $srv->{'status'} .= "Spamcop: " . $answer->string;
    }
    # Barracuda
    if ( my $answer = $res->query( $rev_ip . '.b.barracudacentral.org.', 'A' ) ) {
        $srv->{'up'} = 0;
        $srv->{'status'} .= "Barracuda: " . $answer->string;
    }
    # Spamhaus
    if ( my $answer = $res->query( $rev_ip . '.zen.spamhaus.org.', 'A' ) ) {
        $srv->{'up'} = 0;
        $srv->{'status'} .= "Spamhaus ZEN: " . $answer->string;
    }
    # SORBS
    if ( my $answer = $res->query( $rev_ip . '.new.spam.dnsbl.sorbs.net.', 'A' ) ) {
        $srv->{'up'} = 0;
        $srv->{'status'} .= "SORBS: " . $answer->string;
    }
    # UCEPROTECT L1
    if ( my $answer = $res->query( $rev_ip . '.dnsbl-1.uceprotect.net.', 'A' ) ) {
        $srv->{'up'} = 0;
        $srv->{'status'} .= "UCEPROTECT L1: " . $answer->string;
    }
    # UCEPROTECT L2
    if ( my $answer = $res->query( $rev_ip . '.dnsbl-2.uceprotect.net.', 'A' ) ) {
        $srv->{'up'} = 0;
        $srv->{'status'} .= "UCEPROTECT L2: " . $answer->string;
    }
    # UCEPROTECT L3
    if ( my $answer = $res->query( $rev_ip . '.dnsbl-3.uceprotect.net.', 'A' ) ) {
        $srv->{'up'} = 0;
        $srv->{'status'} .= "UCEPROTECT L3: " . $answer->string;
    }
    # Backscatterer
    if ( my $answer = $res->query( $rev_ip . '.ips.backscatterer.org.', 'A' ) ) {
        $srv->{'up'} = 0;
        $srv->{'status'} .= "Backscatterer: " . $answer->string;
    }
    # Lashback
    if ( my $answer = $res->query( $rev_ip . '.ubl.unsubscore.com.', 'A' ) ) {
        $srv->{'up'} = 0;
        $srv->{'status'} .= "Lashback: " . $answer->string;
    }
    # Nix
    if ( my $answer = $res->query( $rev_ip . '.ix.dnsbl.manitu.net.', 'A' ) ) {
        $srv->{'up'} = 0;
        $srv->{'status'} .= "NiX: " . $answer->string;
    }

    return( "spam", $srv );
}

# Logging ->

sub Log {
    my ( $service, $srv ) = @_;

    #say "Logging:\t$srv->{'name'}\t$srv->{'ip'}\t$service\t$srv->{'port'}\t$srv->{'up'}\t$srv->{'status'}" unless $srv->{'up'};
    LogSQL  ( $service, $srv );
    #LogPushover ( $service, $srv );
    #LogXMPP ( $service, $srv );
    LogPushbullet ( $service, $srv );

    return;
}

sub LogSQL {
    my ( $service, $srv ) = @_;

    unless ( $srv->{'up'} ) {
        my $logQuery = "INSERT INTO log (ip,name,service,port,status,time) VALUES (?,?,?,?,?,now())";
        my $s = $dbh->prepare( $logQuery );
        $s->execute( $srv->{'ip'}, $srv->{'name'}, $service, $srv->{'port'}, $srv->{'status'} ) or croak $dbh->errstr;
    }

    return;
}

sub LogXMPP {
    my ( $service, $srv ) = @_;

    if ( !$srv->{'up'} || $conf->{'debug'} ) {
        my $d = DateTime->now();
        my @to              = ( 'mirko.iannella', );
        my $msg             = $srv->{'name'} . " down @ " . $d->datetime . "\n" . $srv->{'status'};

        my $username = $conf->{'xmpp_user'};
        my $password = $conf->{'xmpp_pass'};
        my $resource = "iMon";

        my $hostname        = $conf->{'xmpp_host'};
        my $port            = $conf->{'xmpp_port'};
        my $componentname   = 'gmail.com';
        my $connectiontype  = 'tcpip';
        my $tls             = 1;

        my $conn = Net::XMPP::Client->new();

        $conn->Connect(
            hostname        => $hostname,
            port            => $port,
            componentname   => $componentname,
            connectiontype  => $connectiontype,
            tls             => $tls
        ) or croak ( "Can't connect to Jabber: $!" );

        # Change hostname (Google's anti-standard mode)
        my $sid = $conn->{SESSION}->{id};
        $conn->{STREAM}->{SIDS}->{$sid}->{hostname} = $componentname;

        my @result = $conn->AuthSend(
            username => $username,
            password => $password,
            resource => $resource
        );
        if ($result[0] ne "ok") {
           croak ( "ERROR: Auth failed: $result[0] - $result[1]\n" );
        }

        foreach ( @to ) {
            $conn->MessageSend(
                to       => "$_\@$componentname",
                resource => $resource,
                subject  => "Server notify",
                type     => "chat",
                body     => $msg,
            );
        }

        $conn->Disconnect();
    }

    return;
}

sub LogPushover {
    my ( $service, $srv ) = @_;

    my $d = DateTime->now();

    if ( !$srv->{'up'} || $conf->{'debug'} ) {
        LWP::UserAgent->new()->post(
            "https://api.pushover.net/1/messages.json", [

                "token"     => $conf->{'pushover_token'},
                "user"      => $conf->{'pushover_user'},
                "title"     => $srv->{'name'} . " requires attention",
                "message"   => $srv->{'status'},
                "sound"     => "falling",

        ]);

    }

    return;
}

sub LogPushbullet {
    my ( $service, $srv ) = @_;

    my $d = DateTime->now();
    my $token = $conf->{'pushbullet_token'};

    if ( !$srv->{'up'} || $conf->{'debug'} ) {
        my $ua = LWP::UserAgent->new();
        $ua->credentials( 'api.pushbullet.com:443', 'Pushbullet', $token => '' );
        my $response = $ua->post(
            'https://api.pushbullet.com/v2/pushes', [
                #device_iden => $conf->{'pushbullet_dev'},
                'type'      => 'note',
                title       => $srv->{'name'} . " requires attention",
                body        => $srv->{'status'},
            ]
        );

        unless( $response->is_success ) {
            say "Risposta da " . $srv->{'name'} . ": " . $response->status_line;
        }

    }

    return;
}


sub get_config {
    my $config_file = shift;
    open( my $confh, '<', "$config_file" )
        or die "Can't open the configuration file '$config_file'.\n";
    my $config = join "", <$confh>;
    close( $confh );
    eval( $config );
}
