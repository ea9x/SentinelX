"""Local-only first account provisioning; never changes an existing account."""
import click
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from models import db,User
from routes.auth import bcrypt,EMAIL_PATTERN


def register_bootstrap(app):
    @app.cli.command('create-initial-admin')
    @click.option('--username',prompt=True)
    @click.option('--email',prompt=True)
    @click.password_option()
    def create_initial_admin(username,email,password):
        """Create the first administrator on an empty installation only."""
        username=username.strip();email=email.strip().lower()
        if not username or len(username)>50 or len(email)>100 or not EMAIL_PATTERN.fullmatch(email):
            raise click.ClickException('Enter a valid username and email address.')
        if len(password)<12 or len(password.encode('utf-8'))>72:
            raise click.ClickException('Use a password of at least 12 characters and at most 72 UTF-8 bytes.')
        from schema import ensure_schema
        ensure_schema()
        try:
            if db.session.execute(select(User.id).with_for_update()).first():
                raise click.ClickException('Accounts already exist. Initial administrator creation is disabled.')
            db.session.add(User(username=username,email=email,role='admin',password_hash=bcrypt.generate_password_hash(password).decode()))
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            raise click.ClickException('Initial administrator creation failed. No existing account was changed.') from None
        click.echo('Initial administrator created. Public registration remains unchanged.')
