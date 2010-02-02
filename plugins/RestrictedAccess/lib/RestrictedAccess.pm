# RestrictedAccess plugin for Movable Type
# Author: Jay Allen, Endevver Consulting
# See README.txt in original distribution for copyright and licensing details
#
# $Id: RestrictedAccess.pm 849 2008-05-21 11:24:56Z jay $

package RestrictedAccess;

use MT::Util qw(encode_html);
use MT::Log qw( INFO WARNING ERROR SECURITY DEBUG );

use MT::Log::Log4perl qw(l4mtdump);
my $logger = MT::Log::Log4perl->new();

sub cb_cfg_system_users_param {
    my $plugin = shift;
    $logger->trace();
    $plugin->runner('insert_fields', @_,
        {   fields      => 'registration',
            target      => 'registration',
            position    => 'after'          });
}

sub cb_cfg_system_general_param {
    my $plugin = shift;
    $logger->trace();
    $plugin->runner('insert_fields', @_,
        {   fields      => 'cms_access',
            target      => 'system_email_address',
            position    => 'after'                 });
}

sub insert_fields {
    my $plugin = shift;
    my ($cb, $app, $param, $tmpl, $args) = @_;
    $logger->trace();

    # Load fields template from the includes directory and
    # populate stash with appropriate varaibles
    $append_text = $plugin->load_fields($tmpl, $args->{fields});
    
    # Create new text node using the generated text
    $new_node = $tmpl->createTextNode($append_text);
    
    # Grab target node that you want to append 
    my $node = $tmpl->getElementById( $args->{target} );
    
    # Insert the created node in the desired position
    if ($args->{position} eq 'before') {
        $tmpl->insertBefore($new_node, $node);        
    }
    else {        
        $tmpl->insertAfter($new_node, $node);
    }
}

sub save_cfg_system_users {
    my $plugin = shift;
    my $app = shift;
    $logger->trace();

    my $cfg                     = $plugin->get_config_hash;
    $cfg->{reg_allowed_domains} = $app->param('reg_allowed_domains');
    
    # $logger->debug('CFG save: ', $plugin->save_config($cfg, 'system'));
    $plugin->save_config($cfg, 'system');
}

sub save_cfg_system_general {
    my $plugin = shift;
    my $app = shift;
    $logger->trace();

    my $cfg    = $plugin->get_config_hash;
    $cfg->{$_} = $app->param($_)
        foreach qw(restrict_cms cms_allowed_users cms_denied_message);
    $logger->debug('$cfg: ', l4mtdump($cfg));
    
    # $logger->debug('CFG save: ', $plugin->save_config($cfg, 'system'));
    $plugin->save_config($cfg, 'system');
}

sub do_register_wrapper {
    my $plugin = shift;
    my $oldsub = shift;
    my $app    = shift;
    $logger->trace();

    my $cfg     = $plugin->get_config_hash;    
    my @allowed = split /[\n\r\s,]+/, $cfg->{reg_allowed_domains};
    # $logger->debug('@allowed: ', l4mtdump(\@allowed));

    if (@allowed) {        
        my $email = $app->param('email');
        my $allowed = 0;
        foreach my $domain (@allowed) {

            # If the string starts with a @, do a straight string
            # comparison to test that the email ends with the given string
            if (index($domain, '@') == 0) {
                # $logger->debug(sprintf 'Checking @ variant for %s: %s',
                #    $domain, (index($email, $domain) != -1));
                next unless index($email, $domain) != -1;
            }
            # If the string starts with a period, we want only
            # SUBdomains under the specified string.
            elsif (index($domain, '.') == 0) {
                # $logger->debug(sprintf 'Checking . variant for %s: %s',
                #     $domain, ($email =~ m!\@(\.?[a-z0-9-_]+){0,2}\b\Q$domain\E$!i));
                next unless
                    $email =~ m!\@(\.?[a-z0-9-_]+){0,2}\b\Q$domain\E$!i;
            }
            # Otherwise, test that the email ends with @STRING allowing
            # for up two optional subdomains.  Must prevent spoofing via
            # longer strings.
            else {
                # $logger->debug(sprintf 'Checking open variant for %s: %s',
                #     $domain, ($email =~ m!\@([a-z0-9-_]+\.){0,2}\b\Q$domain\E$!i));
                next unless
                    $email =~ m!\@([a-z0-9-_]+\.){0,2}\b\Q$domain\E$!i;
            }
            $allowed++;
            last;
        }
        if (!$allowed) {
            my $msg =  $cfg->{reg_denied_message}
                    || $plugin->default_setting('reg_denied_message');
            $msg = $plugin->translate($msg);
            return $app->error($msg);
        }
    }
    $oldsub->($app, @_);
}

sub upgrader_app_lock {
    my $plugin = shift;
    my ($app, $cfg) = @_;
    $logger->trace();

    $logger->warn('$cfg: ', l4mtdump($cfg));
    
    $logger->warn('RestrictedAccess single-user mode enabled during upgrade for: '.$app->user->name);
    # Save old config in upgrade_lockout to serve as a flag
    $cfg->{upgrade_lockout}
        = sprintf '%s:%s', $cfg->{restrict_cms}, $cfg->{cms_allowed_users};
    
    # Enable single-user mode for this user
    $cfg->{restrict_cms}      = 'self';
    $cfg->{cms_allowed_users} = $app->user->name;

    $plugin->save_config($cfg, 'system');
    # $logger->warn('CFG save: ', $plugin->save_config($cfg, 'system'));
    $logger->warn('$cfg: ', l4mtdump($cfg));
}

sub upgrader_app_unlock {
    my $plugin = shift;
    my ($app, $cfg) = @_;
    $logger->trace();
    
    my $cur_schema = MT->instance->schema_version;
    my $old_schema = MT->config->SchemaVersion || 0;

    # Check that schema is up to date and if so revert to pre-upgrade config
    if ($cur_schema == $old_schema) {
        $logger->warn('RestrictedAccess single-user mode disabled after upgrade by: '.$app->user->name);
        # Restore previous config from upgrade_lockout value
        ($cfg->{restrict_cms}, $cfg->{cms_allowed_users})
            = split ':', $cfg->{upgrade_lockout};
        # Reset upgrade lockout
        $cfg->{upgrade_lockout}   = 0;
        # $logger->warn('CFG save: ', $plugin->save_config($cfg, 'system'));
        # $logger->warn('$cfg: ', l4mtdump($cfg));
        $plugin->save_config($cfg, 'system');
    }
}

sub access_check {
    my $plugin = shift;
    my ($cb,$app) = @_;
    $logger->trace();
    
    my $allowed = '';
    
    # ALLOW ACCESS if not running an app mode requiring logged in user
    my $user = $app->user or return $plugin->runner('access_allowed');

    # Load plugin configuration. Relevant keys are:
    #   * restrict_cms
    #   * cms_allowed_users
    #   * cms_denied_message
    my $cfg = $plugin->get_config_hash;
    $logger->debug('$cfg: ', l4mtdump($cfg));

    # UPGRADE CHECK
    # For upgrades, put system into single-user mode and short-circuit
    if (    $app->isa('MT::App::Upgrader')
        and $app->mode eq 'upgrade'
        and ! $cfg->{upgrade_lockout}) {
        $plugin->runner('upgrader_app_lock', $app, $cfg);
        return $plugin->runner('access_allowed');
    }

    if (    $app->isa('MT::App::CMS')
        and $cfg->{upgrade_lockout}
        and $cfg->{cms_allowed_users} eq $user->name) {
        $plugin->runner('upgrader_app_unlock', $app, $cfg);
        return $plugin->runner('access_allowed');
    }

    
    # ALLOW ACCESS is plugin configuration is not restricting access
    return $plugin->runner('access_allowed') unless $cfg->{restrict_cms};


    # ALLOW ACCESS if sysadmins allowed and user is an admin
    my $is_admin = $user->is_superuser();
    my $admin_ok = ($cfg->{restrict_cms} =~ m{^(sysadmin|users)$});
    return $plugin->runner('access_allowed') if $admin_ok and $is_admin;
    

    # ALLOW ACCESS if current user is specified in restrict_cms setting
    my $users_ok  = $cfg->{cms_allowed_users} || '';
    foreach (split(/\s*,\s*/, $users_ok)) {
        return $plugin->runner('access_allowed') if $app->user->name eq $_;
    }

    $logger->debug('ACCESS VARS: ', l4mtdump({
        '$allowed' => $allowed,
        '$is_admin' => $is_admin,
        '$admin_ok' => $admin_ok,
        '$users_ok' => $users_ok,
    }));

    return $plugin->runner('access_denied', $cfg->{cms_denied_message});
}

sub access_denied {
    my $plugin = shift;
    $logger->trace();
    my $denied_msg = shift;

    my $app = MT->instance;

    $logger->warn('User blocked by RestrictedAccess: ', $app->user->name||'');

    # Log message to the activity log detailing access denied action
    my $msg = 'Access to admin interface denied for user \'[_1]\' (ID:[_2])';
    $msg = $plugin->translate($msg, $app->user->name, $app->user->id);
    $plugin->log($msg, { author_id => $app->user->id });

    # Translate access denied message to be shown to user
    $denied_msg ||= $plugin->default_setting('cms_denied_message');
    $denied_msg   = $plugin->translate($denied_msg);
    
    # The crafty trick to send the user back to the login screen
    # with the error message shown above the login fields
    $app->forward('login');
    $app->user(undef);
    return $app->error($denied_msg);
    
}

sub access_allowed {
    my $plugin = shift;
    $logger->trace();
    my $app = MT->instance;

    # Flush any pending log message to the activity log
    my $log = $app->request('restrictedaccess_pending_logmsg') or return;
    my $meth = $log->{code};
    $meth->(@{$log->{data}});
    return undef;
}

# Filter the misleading "So and so logged in successfully"
# log entries but pass all others along untouched. Because of
# localization, we have to do this at both the translate level
# (to compare against English strings) and the log() level to
# filter out the message.
sub login_handler {
    my $plugin = shift;
    my $app = shift;
    $logger->trace();

    my $cfg = $plugin->get_config_hash;
    unless ($cfg->{restrictedaccess_mode}) {
	return ($plugin->{login_method}->($app, @_));
    }

    # Capture the MT::translate() and MT::App::log() methods
    {
    	local $SIG{__WARN__} = sub {  }; 
        $plugin->{translate_method} = \&MT::translate;
        *MT::translate = sub { $plugin->runner('filter_translate', @_) };

    	$plugin->{log_method} = \&MT::App::log;
    	*MT::App::log = sub { $plugin->runner('filter_login_messages', @_) };
    }  

    my @out = $plugin->{login_method}->($app, @_);

    # Return the system methods to the rightful owners
	{
		local $SIG{__WARN__} = sub {  }; 
	    *MT::App::log = $plugin->{log_method};
	    *MT::translate = $plugin->{translate_method};
	}  
    @out;
}

sub filter_login_messages {
    my $plugin = shift;
    my ($app, $param) = @_;
    $logger->trace();

    if (ref $param eq 'HASH') {
        $log_message = $param->{'message'} || '';
    } elsif ((ref $param) && (UNIVERSAL::isa($param, 'MT::Log'))) {
        $log_message = $param->message;
    }
    if ($app->request('restrictedaccess_pending_logmsg')) {
    	$app->request('restrictedaccess_pending_logmsg',
    	    { code => $plugin->{log_method}, data => \@_ });
    	return;
    }
    $plugin->{log_method}->(@_);
}

sub filter_translate {
    my $plugin = shift;
    my ($app, $string) = @_;
    $logger->trace();
    if ($string =~ "User.*?logged in successfully") {
	    $app->request('restrictedaccess_pending_logmsg', 1);
    }
    $plugin->{translate_method}->(@_);
}

1;
