import logging
from pathlib import Path
from typing import Optional

import tomli
from pydantic import BaseModel

from bomsquad.vulndb.config_resolver import ConfigResolver

logger = logging.getLogger(__name__)


class DBConfig(BaseModel):
    path: Path


class Config(BaseModel):
    db: DBConfig
    nvd_api_key: Optional[str] = None
    request_delay: int

    @classmethod
    def load(cls) -> "Config":
        with ConfigResolver.resolve_config().open("rb") as fh:
            obj = tomli.load(fh)["vulndb"]
            nvd_api_key = obj["vulndb"]["nvd_api_key"]
            if "$NVD_API_KEY" in nvd_api_key:
                nvd_api_key = os.environ.get("NVD_API_KEY", nvd_api_key)
            config = Config.parse_obj(obj)

            return config


instance = Config.load()
