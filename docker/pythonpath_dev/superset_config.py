# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# This file is included in the final Docker image and SHOULD be overridden when
# deploying the image to prod. Settings configured here are intended for use in local
# development environments. Also note that superset_config_docker.py is imported
# as a final step as a means to override "defaults" configured here
#
import logging
import os
import sys

from celery.schedules import crontab
from flask_caching.backends.filesystemcache import FileSystemCache

logger = logging.getLogger()

DATABASE_DIALECT = os.getenv("DATABASE_DIALECT")
DATABASE_USER = os.getenv("DATABASE_USER")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
DATABASE_HOST = os.getenv("DATABASE_HOST")
DATABASE_PORT = os.getenv("DATABASE_PORT")
DATABASE_DB = os.getenv("DATABASE_DB")

EXAMPLES_USER = os.getenv("EXAMPLES_USER")
EXAMPLES_PASSWORD = os.getenv("EXAMPLES_PASSWORD")
EXAMPLES_HOST = os.getenv("EXAMPLES_HOST")
EXAMPLES_PORT = os.getenv("EXAMPLES_PORT")
EXAMPLES_DB = os.getenv("EXAMPLES_DB")

# The SQLAlchemy connection string.
SQLALCHEMY_DATABASE_URI = (
    f"{DATABASE_DIALECT}://"
    f"{DATABASE_USER}:{DATABASE_PASSWORD}@"
    f"{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_DB}"
)

# Use environment variable if set, otherwise construct from components
# This MUST take precedence over any other configuration
SQLALCHEMY_EXAMPLES_URI = os.getenv(
    "SUPERSET__SQLALCHEMY_EXAMPLES_URI",
    (
        f"{DATABASE_DIALECT}://"
        f"{EXAMPLES_USER}:{EXAMPLES_PASSWORD}@"
        f"{EXAMPLES_HOST}:{EXAMPLES_PORT}/{EXAMPLES_DB}"
    ),
)


REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_CELERY_DB = os.getenv("REDIS_CELERY_DB", "0")
REDIS_RESULTS_DB = os.getenv("REDIS_RESULTS_DB", "1")

RESULTS_BACKEND = FileSystemCache("/app/superset_home/sqllab")

CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_KEY_PREFIX": "superset_",
    "CACHE_REDIS_HOST": REDIS_HOST,
    "CACHE_REDIS_PORT": REDIS_PORT,
    "CACHE_REDIS_DB": REDIS_RESULTS_DB,
}
DATA_CACHE_CONFIG = CACHE_CONFIG
THUMBNAIL_CACHE_CONFIG = CACHE_CONFIG


class CeleryConfig:
    broker_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_DB}"
    imports = (
        "superset.sql_lab",
        "superset.tasks.scheduler",
        "superset.tasks.thumbnails",
        "superset.tasks.cache",
    )
    result_backend = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_RESULTS_DB}"
    worker_prefetch_multiplier = 1
    task_acks_late = False
    beat_schedule = {
        "reports.scheduler": {
            "task": "reports.scheduler",
            "schedule": crontab(minute="*", hour="*"),
        },
        "reports.prune_log": {
            "task": "reports.prune_log",
            "schedule": crontab(minute=10, hour=0),
        },
    }


CELERY_CONFIG = CeleryConfig

FEATURE_FLAGS = {"ALERT_REPORTS": True}
ALERT_REPORTS_NOTIFICATION_DRY_RUN = True
WEBDRIVER_BASEURL = f"http://superset_app{os.environ.get('SUPERSET_APP_ROOT', '/')}/"  # When using docker compose baseurl should be http://superset_nginx{ENV{BASEPATH}}/  # noqa: E501
# The base URL for the email report hyperlinks.
WEBDRIVER_BASEURL_USER_FRIENDLY = (
    f"http://localhost:8888/{os.environ.get('SUPERSET_APP_ROOT', '/')}/"
)
SQLLAB_CTAS_NO_LIMIT = True

log_level_text = os.getenv("SUPERSET_LOG_LEVEL", "INFO")
LOG_LEVEL = getattr(logging, log_level_text.upper(), logging.INFO)

if os.getenv("CYPRESS_CONFIG") == "true":
    # When running the service as a cypress backend, we need to import the config
    # located @ tests/integration_tests/superset_test_config.py
    base_dir = os.path.dirname(__file__)
    module_folder = os.path.abspath(
        os.path.join(base_dir, "../../tests/integration_tests/")
    )
    sys.path.insert(0, module_folder)
    from superset_test_config import *  # noqa

    sys.path.pop(0)

#
# Optionally import superset_config_docker.py (which will have been included on
# the PYTHONPATH) in order to allow for local settings to be overridden
#
try:
    import superset_config_docker
    from superset_config_docker import *  # noqa: F403

    logger.info(
        "Loaded your Docker configuration at [%s]", superset_config_docker.__file__
    )
except ImportError:
    logger.info("Using default Docker config...")

# ============================================================================
# CORS allow for user images configuration
# ============================================================================
FEATURE_FLAGS = {
    "ENABLE_TEMPLATE_PROCESSING": True,
}

TALISMAN_DEV_CONFIG = {
    "content_security_policy": {
        "base-uri": ["'self'"],
        "default-src": ["'self'"],
        "img-src": [
            "'self'",
            "blob:",
            "data:",
            "https://apachesuperset.gateway.scarf.sh",
            "https://static.scarf.sh/",
            "https://cdn.brandfolder.io",
            "ows.terrestris.de",
            "https://mighzalalarab.com",
            "https://cdn.document360.io",
        ],
        "worker-src": ["'self'", "blob:"],
        "connect-src": [
            "'self'",
            "https://api.mapbox.com",
            "https://events.mapbox.com",
            "https://tile.openstreetmap.org",
            "https://tile.osm.ch",
            "https://a.basemaps.cartocdn.com",
        ],
        "object-src": "'none'",
        "style-src": [
            "'self'",
            "'unsafe-inline'",
        ],
        "script-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
    },
    "content_security_policy_nonce_in": ["script-src"],
    "force_https": False,
    "session_cookie_secure": False,
}

TALISMAN_CONFIG = {
    "content_security_policy": {
        "base-uri": ["'self'"],
        "default-src": ["'self'"],
        "img-src": [
            "'self'",
            "blob:",
            "data:",
            "https://apachesuperset.gateway.scarf.sh",
            "https://static.scarf.sh/",
            # "https://cdn.brandfolder.io", # Uncomment when SLACK_ENABLE_AVATARS is True  # noqa: E501
            "ows.terrestris.de",
            "https://mighzalalarab.com",
            "https://cdn.document360.io",
        ],
        "worker-src": ["'self'", "blob:"],
        "connect-src": [
            "'self'",
            "https://api.mapbox.com",
            "https://events.mapbox.com",
            "https://tile.openstreetmap.org",
            "https://tile.osm.ch",
            "https://a.basemaps.cartocdn.com",
        ],
        "object-src": "'none'",
        "style-src": [
            "'self'",
            "'unsafe-inline'",
        ],
        "script-src": ["'self'", "'strict-dynamic'"],
    },
    "content_security_policy_nonce_in": ["script-src"],
    "force_https": False,
    "session_cookie_secure": False,
}

# ============================================================================
# OAuth/Keycloak Authentication Configuration
# ============================================================================

import base64
import json
import logging

from urllib.parse import urlencode

from flask import flash, redirect, request, session, url_for
from flask_appbuilder.security.manager import AUTH_OAUTH
from flask_appbuilder.security.views import AuthOAuthView, expose
from flask_login import login_user, logout_user

from superset.security import SupersetSecurityManager

logger = logging.getLogger()

# Enable OAuth authentication
AUTH_TYPE = AUTH_OAUTH
ENABLE_PROXY_FIX = True

# Keycloak configuration - read from environment variables (required)
KEYCLOAK_BASE_URL = os.getenv("KEYCLOAK_BASE_URL")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")

# Validate that all Keycloak configuration is provided
if not all([KEYCLOAK_BASE_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET]):
    missing = []
    if not KEYCLOAK_BASE_URL:
        missing.append("KEYCLOAK_BASE_URL")
    if not KEYCLOAK_REALM:
        missing.append("KEYCLOAK_REALM")
    if not KEYCLOAK_CLIENT_ID:
        missing.append("KEYCLOAK_CLIENT_ID")
    if not KEYCLOAK_CLIENT_SECRET:
        missing.append("KEYCLOAK_CLIENT_SECRET")
    
    raise ValueError(
        f"Missing required Keycloak configuration environment variables: {', '.join(missing)}. "
        "Please set these in your environment or .env file."
    )

# Get Superset base URL, accounting for SUPERSET_APP_ROOT if set
# SUPERSET_APP_ROOT = os.environ.get('SUPERSET_APP_ROOT', '')
# SUPERSET_URL = os.getenv("SUPERSET_URL") or f"http://localhost:8088{SUPERSET_APP_ROOT}"

# OAuth provider configuration
# NOTE: Make sure your Keycloak client has these redirect URIs configured.
# If SUPERSET_APP_ROOT is set (e.g., '/superset'), include it in the redirect URIs:
# - http://localhost:8088<SUPERSET_APP_ROOT>/oauth-authorized/keycloak
# - http://localhost:8088<SUPERSET_APP_ROOT>/oauth-authorized/keycloak/ (if using trailing slash)
# Example with SUPERSET_APP_ROOT='/superset':
# - http://localhost:8088/superset/oauth-authorized/keycloak
OAUTH_PROVIDERS = [
    {
        "name": "hakimilabs",
        "icon": "fa-address-card",
        "token_key": "access_token",    
        "remote_app": {
            "client_id": KEYCLOAK_CLIENT_ID,
            "client_secret": KEYCLOAK_CLIENT_SECRET,
            "server_metadata_url": f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration",
            "client_kwargs": {
                "scope": "openid email profile"
            },
        }
    }
]

# CRITICAL: Disable automatic user registration
# Users without proper roles will be rejected
AUTH_USER_REGISTRATION = False

# These are not used as defaults, but required by Superset
# AUTH_ROLE_ADMIN = "Admin"
# AUTH_ROLE_PUBLIC = "Public"

# Session configuration
# SECRET_KEY = "your-secret-key-change-this-to-something-random"
SESSION_COOKIE_SECURE = True  # Set to True if using HTTPS
# SESSION_COOKIE_HTTPONLY = True
# SESSION_COOKIE_SAMESITE = "Lax"

# CSRF configuration
# WTF_CSRF_ENABLED = True
# WTF_CSRF_EXEMPT_LIST = ['']
# WTF_CSRF_TIME_LIMIT = None

# Custom Security Manager
class CustomAuthOAuthView(AuthOAuthView):
    """
    Custom OAuth view that handles Keycloak authentication
    with strict role validation
    """
    # Keep default login page - only override OAuth callback handling
    
    @expose('/oauth-authorized/<provider>')
    def oauth_authorized(self, provider):
        """
        Handle OAuth callback with strict role validation
        """
        logger.info(f"OAuth authorized callback for provider: {provider}")
        
        try:
            # Get the OAuth remote app
            if provider not in self.appbuilder.sm.oauth_remotes:
                logger.error(f"Provider '{provider}' not found in oauth_remotes")
                flash("Authentication failed. Invalid provider.", "danger")
                return redirect(url_for('.login'))
            
            remote = self.appbuilder.sm.oauth_remotes[provider]
            
            # Get the token from the callback
            logger.info("Getting access token from OAuth provider...")
            token = remote.authorize_access_token()
            
            if token is None:
                logger.error("Failed to get token from OAuth provider")
                flash("Authentication failed. Unable to retrieve access token.", "danger")
                return redirect(url_for('.login'))
            
            logger.info("Access token retrieved successfully")
            
            # Get user info with role validation
            logger.info("Getting user info from OAuth provider...")
            me = self.appbuilder.sm.oauth_user_info(provider, token)
            
            if me is None:
                logger.error("Failed to get user info from OAuth provider")
                flash("Authentication failed. Unable to retrieve user information.", "danger")
                return redirect(url_for('.login'))
            
            # CRITICAL: Check if user has valid roles
            if not me.get('role_keys') or len(me.get('role_keys', [])) == 0:
                logger.warning(f"User {me.get('username')} has no valid Superset roles in Keycloak")
                flash("Access Denied: You do not have the required permissions to access Superset. Please contact your administrator.", "danger")
                return redirect(url_for('.login'))
            
            logger.info(f"User info received: {me}")
            
            # Try to authenticate user (will only work if user exists with proper roles)
            user = self.appbuilder.sm.auth_user_oauth(me)
            
            if user is None:
                logger.error(f"Failed to authenticate user: {me.get('username')}. User may not exist or lacks proper roles.")
                flash("Access Denied: Your account is not authorized to access Superset. Please contact your administrator.", "danger")
                return redirect(url_for('.login'))
            
            # Verify user has at least one role assigned
            if not user.roles or len(user.roles) == 0:
                logger.error(f"User {user.username} has no roles assigned in Superset")
                flash("Access Denied: Your account has no roles assigned. Please contact your administrator.", "danger")
                return redirect(url_for('.login'))
            
            # Store ID token in session for Keycloak logout
            if isinstance(token, dict) and 'id_token' in token:
                session['keycloak_id_token'] = token['id_token']
                logger.info("Stored ID token in session for Keycloak logout")
            
            # Log the user in
            login_user(user, remember=False)
            logger.info(f"User logged in successfully: {user.username} with roles: {[r.name for r in user.roles]}")
            
            # Get the next URL from session or args, or redirect to home
            # Use appbuilder.get_url_for_index to respect SUPERSET_APP_ROOT
            default_next = self.appbuilder.get_url_for_index
            next_url = session.pop('next', None) or request.args.get('next', default_next)
            return redirect(next_url)
            
        except Exception as e:
            logger.error(f"OAuth authentication error: {str(e)}", exc_info=True)
            flash("Authentication failed. Please try again or contact your administrator.", "danger")
            return redirect(url_for('.login'))
    
    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        """
        Override logout to also logout from Keycloak (single sign-out)
        """
        logger.info("User logout requested")
        
        # Get ID token from session for Keycloak logout
        id_token = session.pop('keycloak_id_token', None)
        
        # Logout from Superset first
        logout_user()
        logger.info("Logged out from Superset")
        
        # If we have an ID token, redirect to Keycloak logout
        if id_token:
            # Build Keycloak logout URL
            logout_url = (
                f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/"
                f"protocol/openid-connect/logout"
            )
            
            # Build redirect URI to go back to Superset login after Keycloak logout
            redirect_uri = url_for('.login', _external=True)
            
            # Build logout URL with parameters
            params = {
                'id_token_hint': id_token,
                'post_logout_redirect_uri': redirect_uri,
            }
            keycloak_logout_url = f"{logout_url}?{urlencode(params)}"
            
            logger.info(f"Redirecting to Keycloak logout: {keycloak_logout_url}")
            return redirect(keycloak_logout_url)
        else:
            # No ID token, just redirect to login
            logger.warning("No ID token found in session, skipping Keycloak logout")
            return redirect(url_for('.login'))


class CustomSecurityManager(SupersetSecurityManager):
    """
    Custom security manager with:
    1. Strict role validation
    2. No default role assignment
    3. Direct OAuth redirect
    """
    authoauthview = CustomAuthOAuthView
    
    def oauth_user_info(self, provider, response=None):
        """
        Extract user info from Keycloak with STRICT role validation
        Returns None if user has no valid roles
        """
        logger.info(f"Getting user info for provider: {provider}")
        logger.info(f"Response type: {type(response)}, Response keys: {response.keys() if response and isinstance(response, dict) else 'N/A'}")
        
        if provider == "hakimilabs":
            try:
                # Get the remote app
                remote = self.oauth_remotes[provider]
                
                # The response parameter contains the token response from Keycloak
                # Extract access token to decode and get roles
                access_token = None
                if response and isinstance(response, dict):
                    access_token = response.get("access_token")
                    logger.info(f"Token response keys: {list(response.keys())}")
                
                # Fetch user info from Keycloak userinfo endpoint
                resp = remote.get(
                    f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
                )
                
                if resp.status_code != 200:
                    logger.error(f"Failed to get user info: {resp.status_code}, Response: {resp.text}")
                    return None
                
                user_data = resp.json()
                logger.info(f"Raw user data from Keycloak userinfo endpoint: {user_data}")
                
                # Also decode the access token to get roles (roles are in the token, not userinfo)
                token_data = {}
                if access_token:
                    try:
                        # JWT tokens have 3 parts separated by dots: header.payload.signature
                        token_parts = access_token.split('.')
                        if len(token_parts) >= 2:
                            # Decode the payload (second part)
                            # Add padding if needed
                            payload = token_parts[1]
                            payload += '=' * (4 - len(payload) % 4)  # Add padding
                            decoded = base64.urlsafe_b64decode(payload)
                            token_data = json.loads(decoded)
                            logger.info(f"Decoded token data keys: {list(token_data.keys())}")
                            logger.info(f"Token contains realm_access: {'realm_access' in token_data}")
                            logger.info(f"Token contains resource_access: {'resource_access' in token_data}")
                    except Exception as e:
                        logger.warning(f"Could not decode access token: {e}")
                
                # Merge userinfo data with token data (token has roles, userinfo has user details)
                combined_data = {**user_data, **token_data}
                logger.info(f"Combined data keys: {list(combined_data.keys())}")
                
                # Extract user information
                username = combined_data.get("preferred_username") or combined_data.get("email", "").split("@")[0]
                email = combined_data.get("email", "")
                first_name = combined_data.get("given_name", "")
                last_name = combined_data.get("family_name", "")
                
                # CRITICAL: Extract roles with strict validation
                # Pass both userinfo and token data to extract roles
                role_keys = self._extract_roles_from_token(combined_data)
                
                # REJECT users without any valid roles
                if not role_keys or len(role_keys) == 0:
                    logger.warning(f"User {username} has no valid Superset roles. Rejecting authentication.")
                    logger.warning("To fix: Assign roles in Keycloak (superset-admin, alpha, or gamma)")
                    return None
                
                logger.info(f"Extracted user info - username: {username}, email: {email}, roles: {role_keys}")
                
                return {
                    "username": username,
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "role_keys": role_keys
                }
                
            except Exception as e:
                logger.error(f"Error getting user info: {str(e)}", exc_info=True)
                return None
        
        return None
    
    def _extract_roles_from_token(self, user_data):
        """
        Extract and map Keycloak roles to Superset roles
        Returns EMPTY LIST if no valid roles found (user will be rejected)
        """
        roles = []
        
        logger.info("Extracting roles from token/user_data...")
        
        # Method 1: Check realm_access roles (realm-level roles)
        # if "realm_access" in user_data:
        #     realm_roles = user_data["realm_access"].get("roles", [])
        #     logger.info(f"Realm roles found: {realm_roles}")
            
        #     # Map realm-level roles to Superset roles
        #     if "superset-admin" in realm_roles:
        #         roles.append("Admin")
        #     if "superset-alpha" in realm_roles:
        #         roles.append("Alpha")
        #     if "superset-gamma" in realm_roles:
        #         roles.append("Gamma")
        #     # Also check for direct role names (in case roles are named Admin, Alpha, Gamma)
        #     if "Admin" in realm_roles:
        #         roles.append("Admin")
        #     if "Alpha" in realm_roles:
        #         roles.append("Alpha")
        #     if "Gamma" in realm_roles:
        #         roles.append("Gamma")
        
        # Method 2: Check resource_access (client-specific roles)
        if "resource_access" in user_data:
            logger.info(f"resource_access keys: {list(user_data['resource_access'].keys())}")
            
            # Check client-specific roles
            if KEYCLOAK_CLIENT_ID in user_data["resource_access"]:
                client_roles = user_data["resource_access"][KEYCLOAK_CLIENT_ID].get("roles", [])
                logger.info(f"Client roles for {KEYCLOAK_CLIENT_ID}: {client_roles}")
                
                if "superset-admin" in client_roles:
                    roles.append("Admin")
                if "alpha-readonly" in client_roles:
                    roles.append("alpha_readonly")
                if "superset-alpha" in client_roles:
                    roles.append("Alpha")
                if "superset-gamma" in client_roles:
                    roles.append("Gamma")
                # Also check for direct role names
                if "Admin" in client_roles:
                    roles.append("Admin")
                if "Alpha" in client_roles:
                    roles.append("Alpha")
                if "Gamma" in client_roles:
                    roles.append("Gamma")
        
        # Method 3: Check groups (if using Keycloak groups)
        # if "groups" in user_data:
        #     groups = user_data.get("groups", [])
        #     logger.info(f"User groups: {groups}")
            
        #     if "/superset-admin" in groups or "superset-admin" in groups:
        #         roles.append("Admin")
        #     if "/superset-alpha" in groups or "superset-alpha" in groups:
        #         roles.append("Alpha")
        #     if "/superset-gamma" in groups or "superset-gamma" in groups:
        #         roles.append("Gamma")
        
        # Remove duplicates
        roles = list(set(roles))
        
        # CRITICAL: Return empty list if no roles found
        # This will cause authentication to fail
        if not roles:
            logger.warning("No valid Superset roles found in Keycloak token. User will be rejected.")
            logger.warning("Expected roles in Keycloak: superset-admin, alpha, or gamma (for Admin, Alpha, Gamma respectively)")
            return []
        
        logger.info(f"Final mapped roles: {roles}")
        return roles
    
    def auth_user_oauth(self, userinfo):
        """
        Override to prevent user creation and enforce strict role validation
        Only allow existing users with proper roles to login
        """
        # Get existing user
        user = self.find_user(username=userinfo['username'])
        
        if user is None:
            # Check if we should allow registration
            # Since AUTH_USER_REGISTRATION = False, we manually handle this
            
            # ONLY create user if they have valid roles from Keycloak
            if not userinfo.get('role_keys') or len(userinfo.get('role_keys', [])) == 0:
                logger.warning(f"Cannot create user {userinfo['username']} - no valid roles")
                return None
            
            # Create user with the roles from Keycloak
            user = self.add_user(
                username=userinfo['username'],
                first_name=userinfo.get('first_name', ''),
                last_name=userinfo.get('last_name', ''),
                email=userinfo['email'],
                role=self.find_role(userinfo['role_keys'][0])  # Assign first role
            )
            
            if user:
                # Assign all additional roles
                for role_name in userinfo['role_keys']:
                    role = self.find_role(role_name)
                    if role and role not in user.roles:
                        user.roles.append(role)
                self.update_user(user)
                logger.info(f"Created new user: {user.username} with roles: {userinfo['role_keys']}")
        else:
            # Update existing user's roles based on Keycloak
            if userinfo.get('role_keys'):
                # Clear existing roles and assign new ones from Keycloak
                user.roles = []
                for role_name in userinfo['role_keys']:
                    role = self.find_role(role_name)
                    if role:
                        user.roles.append(role)
                
                # Update user info
                user.first_name = userinfo.get('first_name', user.first_name)
                user.last_name = userinfo.get('last_name', user.last_name)
                user.email = userinfo.get('email', user.email)
                
                self.update_user(user)
                logger.info(f"Updated user: {user.username} with roles: {userinfo['role_keys']}")
            else:
                logger.warning(f"User {user.username} has no roles from Keycloak")
                return None
        
        return user

# Use custom security manager
CUSTOM_SECURITY_MANAGER = CustomSecurityManager