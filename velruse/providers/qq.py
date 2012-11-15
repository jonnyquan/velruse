"""QQ Authentication Views"""
from json import loads
from urlparse import parse_qs
import urlparse
import uuid

import requests

from pyramid.httpexceptions import HTTPFound
from pyramid.security import NO_PERMISSION_REQUIRED

from velruse.api import (
    AuthenticationComplete,
    AuthenticationDenied,
    register_provider,
    )
from velruse.exceptions import ThirdPartyFailure, CSRFError
from velruse.settings import ProviderSettings
from velruse.utils import flat_url


class QQAuthenticationComplete(AuthenticationComplete):
    """QQ auth complete"""


def includeme(config):
    config.add_directive('add_qq_login', add_qq_login)
    config.add_directive('add_qq_login_from_settings',
        add_qq_login_from_settings)


def add_qq_login_from_settings(config, prefix='velruse.qq.'):
    settings = config.registry.settings
    p = ProviderSettings(settings, prefix)
    p.update('consumer_key', required=True)
    p.update('consumer_secret', required=True)
    p.update('scope')
    p.update('login_path')
    p.update('callback_path')
    config.add_qq_login(**p.kwargs)


def add_qq_login(config,
                 consumer_key,
                 consumer_secret,
                 scope=None,
                 login_path='/login/qq',
                 callback_path='/login/qq/callback',
                 name='qq'):
    """
    Add a QQ login provider to the application.
    """
    provider = QQProvider(name, consumer_key, consumer_secret, scope)

    config.add_route(provider.login_route, login_path)
    config.add_view(provider.login, route_name=provider.login_route,
        permission=NO_PERMISSION_REQUIRED)

    config.add_route(provider.callback_route, callback_path,
        use_global_views=True,
        factory=provider.callback)

    register_provider(config, name, provider)


class QQProvider(object):
    def __init__(self, name, consumer_key, consumer_secret, scope):
        self.name = name
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.scope = scope

        self.login_route = 'velruse.%s-login' % name
        self.callback_route = 'velruse.%s-callback' % name

    def login(self, request):
        """Initiate a qq login"""
        referer=request.referer
        request.session['opennexturl']=referer
        query_string = request.query_string
        request.session['state_code'] = state_code = uuid.uuid4().hex
        state = "%s&state_code=%s" % (query_string, state_code)
        scope = request.POST.get('scope', self.scope)
        gh_url = flat_url('https://graph.qq.com/oauth2.0/authorize',
            scope=scope,
            client_id=self.consumer_key,
            response_type='code',
            redirect_uri=request.route_url(self.callback_route),
            state=state)
        return HTTPFound(location=gh_url)

    def callback(self, request):
        """Process the qq redirect"""
        state = request.GET.get('state')
        statedata=None
        if state:
            statedata = urlparse.parse_qs(state)
            if 'state_code' in statedata:
                state_code = statedata["state_code"][0]
                if state_code != request.session.get('state_code'):
                    raise CSRFError("CSRF Validation check failed. Request state %s is "
                                    "not the same as session state %s" % (
                        state_code, request.session.get('state_code')
                        ))
        code = request.GET.get('code')
        if not code:
            reason = request.GET.get('error', 'No reason provided.')
            return AuthenticationDenied(reason)

        # Now retrieve the access token with the code
        access_url = flat_url(
            'https://graph.qq.com/oauth2.0/token',
            client_id=self.consumer_key,
            client_secret=self.consumer_secret,
            grant_type='authorization_code',
            redirect_uri=request.route_url(self.callback_route),
            code=code)
        r = requests.get(access_url)
        if r.status_code != 200:
            raise ThirdPartyFailure("Status %s: %s" % (
                r.status_code, r.content))
        access_token = parse_qs(r.content)['access_token'][0]

        # Retrieve profile data
        graph_url = flat_url('https://graph.qq.com/oauth2.0/me',
            access_token=access_token)
        r = requests.get(graph_url)
        if r.status_code != 200:
            raise ThirdPartyFailure("Status %s: %s" % (
                r.status_code, r.content))
        data = loads(r.content[10:-3])
        openid = data.get('openid', '')

        user_info_url = flat_url('https://graph.qq.com/user/get_user_info',
            access_token=access_token,
            oauth_consumer_key=self.consumer_key,
            openid=openid)
        r = requests.get(user_info_url)
        if r.status_code != 200:
            raise ThirdPartyFailure("Status %s: %s" % (
                r.status_code, r.content))
        data = loads(r.content)
        print '%s'%data
        profile = {
            'accounts': [{'domain': 'qq.com', 'userid': openid}],
            'displayName': data['nickname'],
            'gender':data['gender'],
            'preferredUsername': data['nickname'],
            'profile_image_url': data['figureurl'],
            'access_token':access_token,
            'openid':openid
        }
        if statedata is not None and 'next' in statedata:
            profile['next'] = statedata['next'][0]
        cred = {'oauthAccessToken': access_token}
        return QQAuthenticationComplete(profile=profile, credentials=cred)
