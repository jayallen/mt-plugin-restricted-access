# RestrictedAccess plugin for Movable Type
# Author: Jay Allen, Endevver Consulting
# See README.txt in original distribution for copyright and licensing details
#
# $Id: RestrictedAccess.pl 849 2008-05-21 11:24:56Z jay $
package MT::Plugin::RestrictedAccess;
use strict; use 5.006; use warnings;

use MT 4.0;   # requires MT 4.0+
use base 'MT::Plugin';

use constant FILTER_LOGIN_MESSAGES => 1;

# TODO Protect registration of mt-comments.cgi as well

# Public version number
our $VERSION = "2.5";

# Development revision number
our $Revision = ('$Revision: 61 $ ' =~ /(\d+)/);

use Carp qw(croak);
use MT::Log qw( INFO WARNING ERROR SECURITY DEBUG );

our ($plugin, $PLUGIN_MODULE, $PLUGIN_KEY);
MT->add_plugin($plugin = __PACKAGE__->new({
    name => 'RestrictedAccess',
    version => $VERSION,
	key => 'restrictedaccess',
    description => '<__trans phrase="This plugin enables system '
        . 'administrators to restrict access to the MT/MTE administrative '
        . 'interface and registration by domain of the users.">',
    author_name => 'Jay Allen, Endevver Consulting',
    author_link => 'http://endevver.com/',
    system_config_template => \&system_config_template,
    l10n_class => 'RestrictedAccess::L10N',
    settings => new MT::PluginSettings([
        ['restrict_cms',
            { Default => 0, Scope => 'system' }],
        ['upgrade_lockout',
            { Default => 0, Scope => 'system' }],
        ['cms_allowed_users',
            { Default => '', Scope => 'system' }],
        ['cms_denied_message',
            { Default => 'Access to the system is currently restricted.',
              Scope => 'system' }],
        ['reg_allowed_domains',
            { Default => '', Scope => 'system' }],
        ['reg_denied_message',
            { Default => 'Registration is currently '
                        . 'restricted on this system.',
              Scope => 'system' }],
    ]),
}));

use MT::Log::Log4perl qw(l4mtdump);
my $logger = MT::Log::Log4perl->new();

sub init_registry {
    my $plugin = shift;
    $plugin->registry({
        callbacks => {
            'MT::App::Upgrader::pre_run'
                => sub { $plugin->runner('access_check',@_) },
                
            'MT::App::CMS::pre_run'
                => sub { $plugin->runner('access_check',@_) },
                
            'MT::App::CMS::template_param.cfg_system_users'
                => sub { $plugin->runner('cb_cfg_system_users_param', @_) },
                
            'MT::App::CMS::template_param.cfg_system_general'
                => sub { $plugin->runner('cb_cfg_system_general_param', @_) },

            'MT::App::CMS::post_run' => \&post_run,
        },
    });

}

sub init_app {
    my $plugin = shift;
    no warnings 'redefine';

    if (FILTER_LOGIN_MESSAGES) { 
        require MT::App;
        $plugin->{login_method} = \&MT::App::login; 
        *MT::App::login = sub { $plugin->runner('login_handler', @_) }; 
    }   
    
    eval { require MT::App::Community; };
    unless ($@) {        
        my $oldsub = MT::App::Community->can('do_register');
        *MT::App::Community::do_register
            = sub { $plugin->runner('do_register_wrapper', $oldsub, @_)};
    }

    $plugin->SUPER::init_app(@_);
    my ($app) = @_;

}

sub post_run {
    my ($cb, $app) = @_;
    $logger->trace();

    $app ||= MT->instance;

    # We save the plugin data from the incoming request
    # (wedged in place via the app param callbacks) here in post_run
    # because the $app->user isn't populated in the preferred place,
    # init_request.  $app->user is required by the cms_restrict feature
    # in case of Single User mode
    if ($app->isa('MT::App::CMS')) {
        $plugin->runner('save_cfg_system_users', $app)
            if $app->mode eq 'save_cfg_system_users';
        $plugin->runner('save_cfg_system_general', $app)
            if $app->mode eq 'save_cfg_system_general';
    }    
}

sub plugin_module   {
    ($PLUGIN_MODULE = __PACKAGE__) =~ s/^MT::Plugin:://;
    return $PLUGIN_MODULE; }

sub plugin_key      {
    ($PLUGIN_KEY = lc(plugin_module())) =~ s/:+/-/g;  return $PLUGIN_KEY; }


sub runner {
    shift if ref($_[0]) eq ref($plugin);
    my $method = shift;
    my $module = plugin_module();
    eval "require $module;";
    if ($@) { print STDERR $@; $@ = undef; return 1; }
    my $method_ref = $PLUGIN_MODULE->can($method);
    return $method_ref->($plugin, @_) if $method_ref;
    die $plugin->translate('Failed to find method: [_1]',
        join('::', $PLUGIN_MODULE, $method));
}

sub system_config_template {
    my @templates;
    foreach my $fields (qw(cms_access registration)) {
        my $tmpl = $plugin->load_tmpl("include/${fields}.tmpl");
        push @templates, $tmpl if defined $tmpl;
    }    
    return join("\n\n\n\n", map { $_->text } @templates);
}

sub load_fields {
    my $plugin = shift;
    my ($tmpl, $fields) = @_;
    $logger->trace();

    # Get template's context object
    my $ctx = $tmpl->context;

    # Load plugin config and create hash of stored data
    # as well as form control switches for each config key
    my $cfg = $plugin->get_config_hash;    

    my %vars;
    foreach my $key (keys %$cfg) {
        $vars{$key} = $cfg->{$key};                 # Data
        $vars{join('_', $key, $cfg->{$key})} = 1;   # Form control switch
    }

    # Populate template variable stash with hash
    $ctx->var($_, $vars{$_}) foreach keys %vars;

    # Load template containing include text
    my $appendtmpl = $plugin->load_tmpl("include/${fields}.tmpl");

    # Provision template with config vars    
    $appendtmpl->param(\%vars);

    # Build and output template text with MT tags translated
    my $append_text = $plugin->translate_templatized($appendtmpl->output());

    return $append_text;
}

sub default_setting {
    my $plugin = shift;
    my ($key, $scope) = @_;
    $scope ||= 'system';
    my $s = $plugin->settings;
    if ($s && (my $defaults = $s->defaults($scope))) {
        return (defined $key ? $defaults->{$key} : $defaults);
    }
    return undef
}

sub save_config {
    my $plugin = shift;
    my $param  = shift;
    my $scope  = shift;
    my $app    = MT->instance;
    my (@pending_authors);

    # MODE HANDLER: Single-user mode
    if ($param->{restrict_cms} eq 'self') {
        my $username = $app->user->name if $app;

        # Must have $app->user for single-user mode
        # Log attempt and preserve current plugin config settings
        unless ($username) {
            my $msg = 'Could not enable RestrictedAccess single-user mode '
                    . 'for [_1] because the current user could not be '
                    . 'determined.';
            $msg = $plugin->translate($msg, ref($app));
            return $plugin->log($msg, { level => MT::Log::ERROR() });
        }
        
        # Only system admins can enable single-user mode
        # Log attempt and preserve current plugin config settings
        unless ($app->user->is_superuser) {
            my $msg = 'Attempt to enable "single-user" mode for [_1] '
                    . 'by non-system administrator user denied.';
            $msg = $plugin->translate($msg, ref($app));
            return $plugin->log($msg, { author_id => $app->user->id });
        }

        # Set cms_allowed_users to current system administrators name
        $param->{cms_allowed_users} = $username;

    # MODE HANDLER: Sysadmins and selected users
    } elsif ($param->{restrict_cms} eq 'users') {

        # User list sanitization
        # Parse and de-dupe users field and check for valid users
        my @users = split(/\s*,\s*/, $param->{cms_allowed_users});
        my (%seen, @users_ok, @users_bad);
        foreach my $user (@users) {
            next if $user eq '' or $seen{$user}++;
            if (! $plugin->author_exists($user)) {
                push(@users_bad, $user);
                next;
            }
            push(@users_ok, $user);
        }

        # Save sanitized user list back to parameter
        if (@users_ok) {            
            $param->{cms_allowed_users} = join(', ', @users_ok);
        }
        # EXCEPTION: No users remain after sanitization
        # Fallback to sysadmins-only access mode
        else {
            $param->{restrict_cms}      = 'sysadmin';
            $param->{cms_allowed_users} = ''
        }

        # Create warning message for non-existent authors
        if (@users_bad) {            
            my $msg = 'Non-existent author(s) omitted from access '
                    . 'restriction configuration: [_1]';
            $msg = $plugin->translate($msg, join(', ', @users_bad));
            $plugin->log($msg, {    level       => MT::Log::WARNING(),
                                    author_id   => $app->user->id });
        }
    }

    #
    # Log configuration change to activity log
    #
    
    my $msg;
    # RESTRICTIONS BEING ENABLED
    if ($param->{restrict_cms}) {
        my %Mode = ( self       => 'Single-user',
                     sysadmin   => 'Sysadmin-only',
                     users      => 'Selected users' );
        $msg = sprintf('"%s" mode enabled for [_1].',
                        $Mode{$param->{restrict_cms}});
        $msg = $plugin->translate($msg, ref($app));

        if ($param->{restrict_cms} eq 'users') {            
            $msg .= ' '
                  . $plugin->translate('Non-sysadmin users allowed: [_1]',
                        $param->{cms_allowed_users});
        }
    }
    # RESTRICTIONS BEING DISABLED
    else {
        $msg = 'Restrictions disabled for [_1].';
        $msg = $plugin->translate($msg, ref($app));
    }

    $plugin->log($msg, { author_id => $app->user->id });

    $plugin->SUPER::save_config($param, $scope, @_)
        or $plugin->log($plugin->SUPER::errstr,
            { type => MT::Log::ERROR(), author_id => $app->user->id});
}

sub log {
    my ($plugin, $msg, $params) = @_;
    $params ||= {};

    # Handle single hashref argument invocation
    if (defined $msg and (ref($msg)||'') eq 'HASH') {
        $params = $msg;                     # Shift hashref to params
        $msg = delete $params->{message};   # Extract message into $msg
    }

    defined $msg or croak $plugin->translate(
            'Method [_1]->log() called with no log message', __PACKAGE__);


    # Fill in default log object values
    $params = {
        class       => 'system',
        level       => MT::Log::SECURITY(),
        category    => 'restrictedaccess',
        %$params
    };

    my $prefix = '';
    if ($params->{level} == MT::Log::WARNING()) {
        $prefix = $plugin->translate('warning');
    }
    elsif ($params->{level} == MT::Log::ERROR()) {
        $prefix = $plugin->translate('error');
    }

    MT->log({
        message => sprintf('RestrictedAccess%s: %s', $prefix, $msg),
        %$params
    });
    return;
}

# Quick and dirty author check
sub author_exists {
    shift while ref($_[0]);
    my $name = shift or
        die $plugin->translate('Author check requires an author username.');
    require MT::Author;
    MT::Author->count({ name => $name, type => 1 })
}

# Internal config retrieval method
sub get_config_hash {
  my $self = shift;
  my $blog_id = $_[0];    

    require MT::Request;
    my $cfg = MT::Request->instance->cache('restrictedaccess_config') || {};

  unless (keys %$cfg) {
      $cfg = $self->SUPER::get_config_hash(@_);
      MT::Request->instance->cache('restrictedaccess_config', $cfg);
  }
  $cfg;
}

# sub translate {
#     my $plugin = shift;
#     print STDERR 'IN PLUGIN TRANSLATE with: ', $_[0], "\n";
# print STDERR 'L10N CLASS: ',$plugin->{'l10n_class'},"\n";
# $plugin->{'l10n_class'} = 'RestrictedAccess::L10N::en_us';
#     $plugin->SUPER::translate(@_);
# }

1;
