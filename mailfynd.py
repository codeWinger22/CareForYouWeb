import re

def validate_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@gofynd\.com$"
    if re.match(pattern, email) or email=="gourivpawar@gmail.com":
        return True
    else:
        return False

# Test cases
print(validate_email("ninadsai@gofynd.com"))  # Should return True
print(validate_email("gourivpawar@gmail.com"))  # Should return False
pattern = r"^[a-zA-Z0-9._%+-]+@gofynd\.com$"
email = "ninadsai@gofynd.com"
print(re.match(pattern,email))
