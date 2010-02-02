# RestrictedAccess plugin for Movable Type
# Author: Jay Allen, Endevver Consulting
# See README.txt in original distribution for copyright and licensing details
#
# $Id: en_us.pm 15 2007-04-21 20:22:36Z jay $

# RestrictedAccess localization file
#
# This package defines the English phrases used by the plugin
# and can be used as a basis for localization of Comment Challenge
#
# To create a localization, simply do the following:
#
# 1) Create a copy of this file with a name beginning with your
#    language code and ending in '.pm'.  For example, a French
#    localization file would be named 'fr.pm'.
# 2) Translate the strings on the right side of the => operators
#    below or on the following line if following a => operator.
#    You must use a backslash to escape single quotes.
# 3) Replace all occurances of 'en_us' in this file with your
#    own language code
#
package RestrictedAccess::L10N::en_us;
use strict;
use base 'RestrictedAccess::L10N';
use vars qw( %Lexicon );

%Lexicon = (

    #
    # Common strings from plugin templates
    #

    "ACCESS_DENIED_MESSAGE_HINT" =>
    "Show this message to those users who are denied access. HTML is not allowed and will be stripped.",

    #
    # Strings from include/cms_access.tmpl
    #

    'Administrative interface access' => 'Administrative interface access',
    'Allowed:'                        => 'Allowed:',
    'All users'                       => 'All users',
    'You (single-user mode)'          => 'You (single-user mode)',
    'System administrators only'      => 'System administrators only',
    'Other users:'                    => 'Other users:',
    'Deny message:'                   => 'Deny message:',
    
    'System administrators and selected users...' =>
    'System administrators and selected users...',

    'RESTRICTEDACCESS_MODE_DESCRIPTION' =>
        'This option enables system access restrictions.',

    'ALLOWED_USERS_DESCRIPTION' =>
        'You can restrict access to the system to either system administrators, a comma-delimited list of specific users (by username) or a combination of both.  At least one valid user must have access for the plugin to be enabled.',

    #
    # Strings from include/registration.tmpl
    #

    'User Registration'    => 'User Registration', 
    'Restrict to domains:' => 'Restrict to domains:',
    'Deny message:'        => 'Deny message:',

    'REG_DOMAIN_DESCRIPTION' =>
    'Restrict registration to only those users with email addresses in specific domains. Separate domains with a carriage return. Prefix with \'@\' to exclude subdomains (e.g. example.com also allows mail.example.com, corp.example.com, et al.  @example.com does not.).',
    
    #
    # Strings within the application code
    #

    'This plugin enables system administrators to restrict access to the MT/MTE administrative interface and registration by domain of the users.' =>
    'This plugin enables system administrators to restrict access to the MT/MTE administrative interface and registration by domain of the users.',

    'Access to the system is currently restricted.' =>
    'Access to the system is currently restricted.',

    'Registration is currently restricted on this system.' =>
    'Registration is currently restricted on this system.',

    'Failed to find method: [_1]' =>
    'Failed to find method: [_1]',

    'Could not enable RestrictedAccess single-user mode for [_1] because the current user could not be determined.' =>
    'Could not enable RestrictedAccess single-user mode for [_1] because the current user could not be determined.',

    'Attempt to enable "single-user" mode for [_1] by non-system administrator user denied.' =>
    'Attempt to enable "single-user" mode for [_1] by non-system administrator user denied.',

    'Non-existent author(s) omitted from access restriction configuration: [_1]' =>
    'Non-existent author(s) omitted from access restriction configuration: [_1]',
    
    '"Single-user" mode enabled for [_1].' =>
    '"Single-user" mode enabled for [_1].',
    
    '"Sysadmin-only" mode enabled for [_1].' =>
    '"Sysadmin-only" mode enabled for [_1].',
    
    '"Selected users" mode enabled for [_1].' =>
    '"Selected users" mode enabled for [_1].',
    
    'Non-sysadmin users allowed: [_1]' =>
    'Non-sysadmin users allowed: [_1]',
    
    'Restrictions disabled for [_1].' =>
    'Restrictions disabled for [_1].',
    
    'Method [_1]->log() called with no log message' =>
    'Method [_1]->log() called with no log message',
    
    'warning' => 'warning',

    'error' => 'error',
    
    'Author check requires an author username.' =>
    'Author check requires an author username.', 
    
    'Access to admin interface denied for user \'[_1]\' (ID:[_2])' =>
    'Access to admin interface denied for user \'[_1]\' (ID:[_2])',

);

if ($MT::VERSION < 3.3) {
    require MT::L10N::en_us;
    $MT::L10N::en_us::Lexicon{$_} = $Lexicon{$_}
        foreach keys %Lexicon;
}

1;
