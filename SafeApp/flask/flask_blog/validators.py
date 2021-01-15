import re
from wtforms.validators import ValidationError

class Password(object):
    def __init__(self, message=None):
        self.message = message

    def __call__(self, form, field):
        message = ''
        if not any(c.islower() for c in field.data):
            message +=  'Hasło musi zawierać co najmniej jedną małą literę. '
            #raise ValidationError('The password must include at least one lowercase letter.')
        if not any(c.isupper() for c in field.data):
            message +=  'Hasło musi zawierać co najmniej jedną wielką literę. '
            #raise ValidationError('The password must include at least one uppercase letter.')
        if not re.search("[0-9]", field.data):
            message +=  'Hasło musi zawierać co najmniej jedną cyfrę. '
            #raise ValidationError('The password must include at least one digit.')
        if not re.search("\W", field.data):
            message += 'Hasło musi zawierać co najmniej jeden znak specjalny. '
            #raise ValidationError('The password must include at least one special character.')
        if message != '':
            raise ValidationError(message)
class Username(object):
    def __init__(self, message=None):
        self.message = message

    def __call__(self, form, field):
        if re.search("\W", field.data):
            raise ValidationError('Nazwa użytkownika może zawierać tylko wielkie litery, małe litery, cyfry i podkreślenie ( _ ).')

def validate_password(form, password):
    if form.is_encrypted.data == True and len(password.data) == 0:
        raise ValidationError('To pole jest wymagane.')