"""Validate and encrypt transient, owner-scoped web scan configuration."""
import base64
import hashlib
import json
from urllib.parse import unquote, urlsplit
from cryptography.fernet import Fernet
from flask import current_app


def local_path(value):
    if not isinstance(value, str) or not value.startswith('/') or len(value) > 2048:
        raise ValueError('Use a target-relative path starting with /.')
    parsed = urlsplit(value)
    decoded = unquote(value)
    if parsed.scheme or parsed.netloc or parsed.fragment or '\\' in decoded or any(ord(c) < 32 for c in decoded) or decoded.startswith('//'):
        raise ValueError('Paths must remain on the selected target.')
    if any(part in {'.', '..'} for part in unquote(parsed.path).split('/')):
        raise ValueError('Path traversal is not allowed.')
    return value


def validate_options(value):
    if not isinstance(value, dict) or len(json.dumps(value)) > 24000:
        raise ValueError('Scan options must be a JSON object smaller than 24 KB.')
    allowed = {'openapi_path', 'paths', 'accounts', 'authorization_checks', 'query_checks','scan_mode','authenticated_zap','login_injection_checks'}
    if set(value) - allowed:
        raise ValueError('Unknown web scan option.')
    if value.get('scan_mode','focused') not in {'focused','comprehensive'}:
        raise ValueError('Scan mode must be focused or comprehensive.')
    if not isinstance(value.get('authenticated_zap', False), bool):
        raise ValueError('authenticated_zap must be a boolean.')
    if value.get('authenticated_zap') and not value.get('accounts'):
        raise ValueError('Authenticated ZAP requires a verified test account.')
    if value.get('authenticated_zap') and not (isinstance(value['accounts'],list) and value['accounts'] and isinstance(value['accounts'][0],dict) and value['accounts'][0].get('login')):
        raise ValueError('Authenticated ZAP requires JSON login for account 1. Header accounts support direct API checks.')
    if value.get('openapi_path'):
        local_path(value['openapi_path'])
    for key in ['paths', 'query_checks']:
        paths = value.get(key, [])
        if not isinstance(paths, list) or len(paths) > 20:
            raise ValueError(f'{key} must be a list of at most 20 paths.')
        for path in paths: local_path(path)
    accounts = value.get('accounts', [])
    if not isinstance(accounts, list) or len(accounts) > 2:
        raise ValueError('Configure at most two test accounts.')
    for account in accounts:
        if not isinstance(account, dict) or set(account) - {'headers', 'login', 'verify_path', 'verify_marker'}:
            raise ValueError('Invalid account configuration.')
        headers = account.get('headers', {})
        if not isinstance(headers, dict) or set(headers) - {'Authorization', 'Cookie'}:
            raise ValueError('Only Authorization and Cookie authentication headers are supported.')
        for item in headers.values():
            if not isinstance(item, str) or not item or len(item) > 6000 or any(ord(c) < 32 for c in item):
                raise ValueError('Invalid authentication header.')
        login = account.get('login')
        if login:
            if not isinstance(login, dict) or set(login) - {'path', 'json', 'token_field'}:
                raise ValueError('Invalid JSON login configuration.')
            local_path(login.get('path'))
            if not isinstance(login.get('json'), dict) or not isinstance(login.get('token_field'), str) or not login['token_field']:
                raise ValueError('JSON login requires a body and dotted token_field.')
        if not headers and not login:
            raise ValueError('Each account requires authentication headers or a JSON login.')
        local_path(account.get('verify_path'))
        if not isinstance(account.get('verify_marker'), str) or not 3 <= len(account['verify_marker']) <= 200:
            raise ValueError('Each account requires a distinctive verification marker.')
    if not isinstance(value.get('login_injection_checks',False),bool):
        raise ValueError('login_injection_checks must be a boolean.')
    if value.get('login_injection_checks'):
        login=accounts[0].get('login') if accounts else None
        body=login.get('json',{}) if isinstance(login,dict) else {}
        field='email' if 'email' in body else 'username'
        if not login or not isinstance(body.get(field),str) or not isinstance(body.get('password'),str):
            raise ValueError('Login injection checks require JSON email or username and password for account 1.')
    checks = value.get('authorization_checks', [])
    if not isinstance(checks, list) or len(checks) > 10 or (checks and len(accounts) != 2):
        raise ValueError('Authorization checks require two accounts and at most ten cases.')
    for check in checks:
        if not isinstance(check, dict) or set(check) != {'path_a', 'path_b', 'marker_a', 'marker_b'}:
            raise ValueError('Each authorization case needs path_a, path_b, marker_a and marker_b.')
        local_path(check['path_a']); local_path(check['path_b'])
        if check['path_a'] == check['path_b'] or check['marker_a'] == check['marker_b']:
            raise ValueError('Use distinct owned resources and markers for each account.')
        if any(not isinstance(check[k], str) or not 3 <= len(check[k]) <= 200 for k in ['marker_a', 'marker_b']):
            raise ValueError('Resource markers must contain 3 to 200 characters.')
    return value


def _cipher():
    secret = current_app.config['SECRET_KEY']
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(('scan-options-v1:'+secret).encode()).digest()))


def encrypt_options(options):
    return _cipher().encrypt(json.dumps(options).encode()).decode() if options else None


def decrypt_options(encrypted):
    return json.loads(_cipher().decrypt(encrypted.encode())) if encrypted else {}
