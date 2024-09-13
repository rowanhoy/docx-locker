from .encrypt import generate_docx_protection

def apply_docx_protection(docpath: str, password: str, salt: str = "" ) -> None:
    encryption = generate_docx_protection(password, salt)
    return encryption