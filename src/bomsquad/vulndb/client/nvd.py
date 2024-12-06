import json
import logging
import time
from abc import abstractmethod
from datetime import datetime
from datetime import timezone
from functools import cached_property
from typing import Any
from typing import Generator
from typing import Generic
from typing import Iterator
from typing import Optional
from typing import TypeVar
from urllib.parse import quote as urlquote

from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from bomsquad.vulndb.config import instance as config
from bomsquad.vulndb.model.cpe import CPE
from bomsquad.vulndb.model.cve import CVE

logger = logging.getLogger(__name__)


T = TypeVar("T", CVE, CPE)


class NVDResultSet(Generic[T]):
    results_per_page: int
    start_index: int
    total_results: int
    version: str
    timestamp: datetime

    _results: dict[str, Any]
    _result_key: str
    _limit: int | None

    _result_iterator: Iterator[dict[str, Any]]
    _result_count: int

    def __init__(self, result_key: str, results: dict[str, Any], limit: int | None = None) -> None:
        self.results_per_page = results["resultsPerPage"]
        self.start_index = results["startIndex"]
        self.total_results = results["totalResults"]
        self.version = results["version"]
        self.timestamp = datetime.fromisoformat(results["timestamp"])

        self._results = results
        self._result_key = result_key
        self._limit = limit

        self._result_iterator = iter(self._results[self._result_key])
        self._result_count = 0

    def __iter__(self) -> Iterator[T]:
        return self

    def __next__(self) -> T:
        if self._limit and self._result_count > self._limit:
            raise StopIteration()
        self._result_count += 1

        return self._to_record(next(self._result_iterator))

    # Since TypeVars do not permit invocation of static methods, we will solve
    # this part rather stupidly with inheritance.
    @abstractmethod
    def _to_record(self, result: dict[str, Any]) -> T:
        pass


class CPEResultSet(NVDResultSet[CPE]):
    def _to_record(self, result: dict[str, Any]) -> CPE:
        return CPE.model_validate(result["cpe"])


class CVEResultSet(NVDResultSet[CVE]):
    def _to_record(self, result: dict[str, Any]) -> CVE:
        return CVE.model_validate(result["cve"])


class NVD:
    CVE_STEM = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CPE_STEM = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

    @cached_property
    def _requests(self) -> Session:
        session = Session()
        retry_policy = Retry(
            total=config.retry_tries,  # maximum number of retries
            backoff_factor=2,  # base backoff factor
            backoff_jitter=config.retry_backoff,  # add retry_backoff as jitter
            backoff_max=config.retry_max_delay,  # cap the max
            status_forcelist=[500, 502, 503, 504],  # the HTTP status codes to retry on
        )
        retry_adapter = HTTPAdapter(max_retries=retry_policy)
        session.mount("https://", retry_adapter)
        return session

    def vulnerabilities(
        self,
        offset: int = 0,
        limit: Optional[int] = None,
        last_mod_start_date: Optional[datetime] = None,
    ) -> Generator[NVDResultSet[CVE], None, None]:
        while True:
            url = f"{self.CVE_STEM}?startIndex={offset}"
            log_msg = f"Querying from index: {offset} to {limit}"
            if last_mod_start_date:
                dtstart = last_mod_start_date.isoformat()
                dtend = datetime.now(timezone.utc).isoformat()
                url += f"&lastModStartDate={urlquote(dtstart)}&lastModEndDate={urlquote(dtend)}"
                log_msg += f" and date: {dtstart} to {dtend}"
            logger.info(log_msg)
            headers = {"Accept": "application/json"}
            if config.nvd_api_key:
                headers["apiKey"] = config.nvd_api_key

            r = self._requests.get(url, headers=headers)
            if r.status_code != 200:
                r.raise_for_status()

            results = CVEResultSet("vulnerabilities", json.loads(r.text), limit)
            if results.total_results > 0 and results.results_per_page > 0:
                offset += results.results_per_page
                yield results
            else:
                break

            time.sleep(config.request_delay)

    def products(
        self,
        offset: int = 0,
        limit: Optional[int] = None,
        last_mod_start_date: Optional[datetime] = None,
    ) -> Generator[NVDResultSet[CPE], None, None]:
        while True:
            url = f"{self.CPE_STEM}?startIndex={offset}"
            if last_mod_start_date:
                dtstart = last_mod_start_date.isoformat()
                dtend = datetime.now(timezone.utc).isoformat()
                url += f"&lastModStartDate={urlquote(dtstart)}&lastModEndDate={urlquote(dtend)}"
                logger.info(f"Querying from {offset} - {limit} and {dtstart} - {dtend}")
            headers = {"Accept": "application/json"}
            if config.nvd_api_key:
                headers["apiKey"] = config.nvd_api_key

            r = self._requests.get(url, headers=headers)
            if r.status_code != 200:
                r.raise_for_status()

            results = CPEResultSet("products", json.loads(r.text), limit)
            if results.total_results > 0 and results.results_per_page > 0:
                offset += results.results_per_page
                yield results
            else:
                break

            time.sleep(config.request_delay)
