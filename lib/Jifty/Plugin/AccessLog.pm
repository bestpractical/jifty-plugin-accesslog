package Jifty::Plugin::AccessLog;
use strict;
use warnings;
use base qw/Jifty::Plugin Class::Data::Inheritable/;
__PACKAGE__->mk_accessors(qw/path format start respect_proxy partials partial_fh/);

use Jifty::Util;
use Time::HiRes qw();

our $VERSION = 1.1;

=head1 NAME

Jifty::Plugin::AccessLog - Concisely log Jifty requests

=head1 DESCRIPTION


=head1 USAGE

Add the following to your site_config.yml

 framework:
   Plugins:
     - AccessLog: {}

=head2 OPTIONS

=over 4

=item path

The file to log to; defaults to F<log/access_log>.

=item respect_proxy

If set to a true value, will display the C<X-Forwarded-For> header as
the originating IP of requests.

=item format

The format string to use when logging.  This module attempts to be as
Apache-compatible as possible; it supports the following format
escapes:

=over

=item %%

The percent sign.

=item %a

Remote IP address.

=item %{Foobar}C

The contents of the cookie I<Foobar> in the request sent to the
server.

=item %D

The time taken to serve the request, in micoseconds.

=item %h

Remote IP address.

=item %{Foobar}n

The content of the I<Foobar> header line(s) in the request.

=item %l

The first 8 characters of the session ID, if any.

=item %m

The request method.

=item %{Foobar}n

The value of the template or request argument I<Foobar>, as sent by
the client, or set in the dispatcher.

=item %{Foobar}o

The value of the I<Foobar> header line(s) in the response.

=item %p

The canonical port of the server serving the request.  Alternate forms
include C<%{canonical}p>, C<%{local}p>, and C<%{remote}p>, which are
the respective connection ports.

=item %P

The process ID that serviced the request.

=item %s

The status code of the response.

=item %t

The time the request was recieved, formatted in Apache's default
format string (C<[%d/%b/%Y:%T %z]>).  C<%{I<format>}t> can be used to
provide a C<strftime>-style custom I<format>.

=item %T

The time taken to serve the request, in seconds.

=item %u

The value of L<Jifty::CurrentUser/username>, if any.

=item %U

The path requested.  In the event that the request was for one or more
regions, the list of regions will be given in square brackets.

=item %v

The canonical server name of the server.

=item %x

The list of active actions run in the request.  Failed actions will be
followed with an exclamation mark, un-run actions with a tilde.

=item %X

As C<%X>, but also includes all argument values to each action.

=back

=item partials

The prefix to log partial logfiles to.  These files are written to as
soon as a request comes in, and truncated back to empty after it is
written to the final logfile.  Non-empty partial logfiles contain
requests which are the cause of critical errors, and should be
examined more closely.

=back

=head2 METHODS

=head2 init

Installs the trigger for each request.

=cut

sub init {
    my $self = shift;
    my %args = (
        path => 'log/access_log',
        format => '%h %l %u %t %m %U %s %T %x',
        @_,
    );

    return if $self->_pre_init;

    $self->path(Jifty::Util->absolute_path( $args{path} ));
    $self->format($args{format});
    $self->respect_proxy($args{respect_proxy});
    Jifty::Handler->add_trigger(
        before_cleanup => sub { $self->before_cleanup }
    );

    Jifty::Handler->add_trigger(
        have_request => sub { $self->have_request },
    ) if $self->partials;
}

=head2 new_request

On each request, log when it starts.

=cut

sub new_request {
    my $self = shift;
    $self->start(Time::HiRes::time);
}

=head2 format_req

Return the formatted string to log

=cut

sub format_req {
    my $self = shift;
    my $r    = Jifty->web->request;

    my $actions = sub {
        my $long = shift;

        my $one_action = sub {
            my $a = shift;
            my $base = $a->class;
            my $result = Jifty->web->response->result($a->moniker);
            $base .= "~" if not $a->has_run or not $result;
            $base .= "!" if $result and not $result->success;
            return $base unless $long;
            return "($base={"
                . join( ",",
                map { "$_=" . $a->argument($_) } keys %{ $a->arguments } )
                . "})"
        };
        return sub {
            my @a = grep { $_->active } $r->actions;
            return "-" unless @a;
            ( $r->just_validating ? "V" : "" ) . "<" . join(
                ", ",    map {$one_action->($_)} @a) . ">";
        }
    };

    my %ESCAPES = (
        '%' => sub { '%' },
        a => sub { ($self->respect_proxy && $r->header("X-Forwarded-For")) || $r->address },
        C => sub { $r->cookies->{+shift} },
        D => sub { sprintf "%.3fms", (Time::HiRes::time - $self->start)*1000 },
        e => sub { $r->env->{+shift} },
        h => sub { ($self->respect_proxy && $r->header("X-Forwarded-For")) || $r->remote_host || $r->address },
        i => sub { $r->header(shift) },
        l => sub { substr( Jifty->web->session->id || '-', 0, 8 ) },
        m => sub { $r->method },
        n => sub { $r->template_argument($_[0]) || $r->argument($_[0]) },
        o => sub { $self->start and Jifty->web->response->header(shift) },
        p => sub {
            return Jifty->config->framework("Web")->{Port} if $_[0] eq "canonical";
            return $r->env->{SERVER_PORT} if $_[0] eq "local";
            return $r->env->{REMOTE_PORT} if $_[0] eq "remote";
            return Jifty->config->framework("Web")->{Port};
        },
        P => sub { $$ },
        s => sub { $self->start and Jifty->web->response->status =~ /^(\d+)/ and $1 },
        t => sub { $self->start and DateTime->from_epoch(epoch => $self->start)->strftime(shift || "[%d/%b/%Y:%T %z]") },
        T => sub { $self->start and sprintf("%.3fs", (Time::HiRes::time - $self->start)) },
        u => sub { $self->start and Jifty->web->current_user->username },
        U => sub {
            if (my @f = $r->fragments) {
                return '[' . join(" ", map {s/ /%20/g;$_} map {$_->path} @f ) . ']';
            } else {
                my $path = $r->path;
                $path =~ s/ /%20/g;
                return $path;
            }
        },
        v => sub { URI->new(Jifty->config->framework("Web")->{BaseURL})->host },
        x => $actions->(0),
        X => $actions->(1),
    );

    my $replace = sub {
        my ($only_on, $string, $format) = @_;
        if (defined $only_on) {
            return "" unless defined Jifty->web->response->status;
            return "" unless grep {Jifty->web->response->status eq $_} split /,/, $only_on;
        }
        my $r;
        if (exists $ESCAPES{$format}) {
            $r = eval { $ESCAPES{$format}->($string) };
            $self->log->warn("While formatting $format, got $@") if $@;
        } else {
            $r = "%".$format;
        }
        return defined $r ? $r : "-";
    };

    my $s = $self->format;
    $s =~ s/%(\d+(?:,\d+)*)?(?:{(.*?)})?([a-zA-Z%])/$replace->($1,$2,$3)/ge;
    return $s;
}

=head2 before_cleanup

Write the access log line to the file

=cut

sub before_cleanup {
    my $self = shift;
    open my $access_log, '>>', $self->path or do {
        $self->log->error("Unable to open @{[$self->path]} for writing: $!");
        return;
    };
    $access_log->syswrite( $self->format_req . "\n" );
    $access_log->close;
    $self->start(undef);
    # Once the request has been written to the actual access log, we
    # purge the partial request from disk
    if ($self->partial_fh) {
        seek($self->partial_fh, 0, 0);
        truncate($self->partial_fh, 0);
    }
}

=head2 have_request

Write the incoming request to the partial logfile; this is only called
if partial logfiles are configured.

=cut

sub have_request {
    my $self = shift;
    unless ($self->partial_fh) {
        open my $fh, ">>", $self->partials.$$ or do {
            $self->log->error("Unable to open @{[$self->partials]}$$ partial for writing: $!");
            return;
        };
        $self->partial_fh($fh);
    }
    $self->partial_fh->syswrite( $self->format_req . "\n" );
}

=head2 END

When the process terminates, remove partial logfiles which are empty.

=cut

END {
    # Purge any empty partial request logs, but leave ones which have
    # data in them
    for my $plugin (grep {$_->isa("Jifty::Plugin::AccessLog") and $_->partial_fh} Jifty->plugins) {
        next if $plugin->partial_fh->tell;
        $plugin->partial_fh->close;
        unlink($plugin->partials.$$);
    }
}

=head1 SEE ALSO

L<Jifty::Plugin::Recorder> for more verbose debugging information.

=head1 COPYRIGHT AND LICENSE

Copyright 2009 Best Practical Solutions

This is free software and may be modified and distributed under the same terms as Perl itself.

=cut

1;
