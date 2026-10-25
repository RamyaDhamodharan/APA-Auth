from sqlalchemy.orm import Session

from src.models.user_models import User
from src.services.password_services import hash_password, verify_password


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.query(User).filter(User.email == email.lower()).first()


def hash_new_password(password: str) -> str:
    return hash_password(password)


def check_password(password: str, password_hash: str) -> bool:
    return verify_password(password, password_hash)
