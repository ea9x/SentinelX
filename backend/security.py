"""Small database-backed request guards for the single-service local deployment."""
import hashlib
import time
from urllib.parse import urlsplit
from flask import request, jsonify
from sqlalchemy.exc import IntegrityError
from models import AuthRateLimit, db

LIMITS = {'targets.check_target_readiness':(10,60), 'auth.login':(10,60), 'auth.register':(5,600),
          'auth.forgot_password':(5,600), 'auth.reset_forgotten_password':(10,60)}

def install_security(app):
    if len(str(app.config.get("SECRET_KEY") or "")) < 32:
        raise RuntimeError("Configure SECRET_KEY with at least 32 random characters before starting SentinelX.")
    @app.before_request
    def guard_request():
        if request.method not in {'POST','PUT','PATCH','DELETE'}:
            return None
        origin = request.headers.get('Origin')
        if origin:
            allowed = {app.config['PUBLIC_APP_URL'].rstrip('/'), request.host_url.rstrip('/')}
            public = urlsplit(app.config['PUBLIC_APP_URL'])
            if public.hostname in {'localhost','127.0.0.1','::1'}:
                # Both spellings are used by the local launcher and browser.
                allowed.update({f'{public.scheme}://{host}:{public.port}' for host in ['localhost','127.0.0.1']})
            if origin.rstrip('/') not in allowed:
                return jsonify(error='This request origin is not allowed.'),403
        limit = LIMITS.get(request.endpoint)
        if not limit:
            return None
        maximum,seconds = limit
        now = int(time.time()); expires = (now//seconds+1)*seconds
        # Never trust a caller-supplied X-Forwarded-For as a rate-limit identity.
        key = hashlib.sha256(f'{request.endpoint}:{request.remote_addr}:{expires}'.encode()).hexdigest()
        AuthRateLimit.query.filter(AuthRateLimit.expires_at <= now).delete(synchronize_session=False)
        updated = AuthRateLimit.query.filter(AuthRateLimit.key==key,AuthRateLimit.hits<maximum).update({'hits':AuthRateLimit.hits+1},synchronize_session=False)
        if updated:
            db.session.commit();return None
        if not db.session.get(AuthRateLimit,key):
            db.session.add(AuthRateLimit(key=key,hits=1,expires_at=expires))
            try:
                db.session.commit();return None
            except IntegrityError:
                db.session.rollback()
                updated = AuthRateLimit.query.filter(AuthRateLimit.key==key,AuthRateLimit.hits<maximum).update({'hits':AuthRateLimit.hits+1},synchronize_session=False)
                if updated:
                    db.session.commit();return None
        db.session.commit()
        response=jsonify(error='Too many attempts. Please try again later.')
        response.status_code=429;response.headers['Retry-After']=str(max(1,expires-now))
        return response

    @app.after_request
    def protect_response(response):
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['Content-Security-Policy']="default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        if request.path.startswith('/api/'):
            response.headers['Cache-Control']='no-store'
        return response

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify(error='Request body exceeds the 64 KB limit.'),413
