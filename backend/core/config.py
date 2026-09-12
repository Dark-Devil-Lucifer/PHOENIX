import os

from dotenv import load_dotenv

load_dotenv()

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PHOENIX_ENV: str = "development"
    PHOENIX_HOST: str = "127.0.0.1"
    PHOENIX_PORT: int = 8000

    DB_HOST: str = "127.0.0.1"
    DB_PORT: int = 3306
    DB_NAME: str = "phoenix"
    DB_USER: str = "phoenix_user"
    DB_PASSWORD: str = ""

    JWT_SECRET_KEY: str = ""
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )


settings = Settings()
