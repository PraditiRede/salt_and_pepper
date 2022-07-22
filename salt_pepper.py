import hashlib, os
def hash_pwd(password):
# Hash, salt to be stored in DB
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode("ascii") 
    pepper = b"M"
    password = password.encode("utf-8")
    pwdhash = hashlib.sha512(password + salt + pepper).hexdigest() 
    return salt.decode("ascii") + pwdhash
def verify_pwd(salt, stored_password, provided_password): 
    pepper = b"M"
    pwd_hash = hashlib.sha512(provided_password.encode("utf8") + salt.encode("ascii") + pepper).hexdigest()
    return pwd_hash == stored_password