from app import create_app
from app.auth.forms import LoginForm, RegistrationForm
from flask import render_template

app = create_app('development')

with app.test_request_context('/'):
    login_form = LoginForm()
    reg_form = RegistrationForm()
    login_html = render_template('auth/login.html', form=login_form)
    reg_html = render_template('auth/register.html', form=reg_form)
    print('login_fields', [f.name for f in login_form])
    print('reg_fields', [f.name for f in reg_form])
    print('login_has_csrf', 'csrf_token' in login_html)
    print('register_has_csrf', 'csrf_token' in reg_html)
    print('login_has_password_toggle', 'password-toggle' in login_html)
    print('register_has_password_toggle', 'password-toggle' in reg_html)
