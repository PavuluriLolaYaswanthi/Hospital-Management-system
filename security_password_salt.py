import secrets
security_password_salt = secrets.token_hex(16)  

print(security_password_salt)
