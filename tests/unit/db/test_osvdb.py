import logging
from contextlib import AbstractContextManager
from contextlib import nullcontext as does_not_raise
from datetime import datetime
from pathlib import Path
from typing import List

import pytest
from packageurl import PackageURL
from tests.factory import CreditFactory
from tests.factory import OpenSSFFactory

from bomsquad.vulndb.db.error import RecordNotFoundError
from bomsquad.vulndb.db.osvdb import instance as osvdb
from bomsquad.vulndb.model.openssf import OpenSSF

logger = logging.getLogger(__name__)


class TestOSVDB:
    @pytest.mark.parametrize(
        ("id", "expectation"),
        [
            ("GHSA-9xjr-m6f3-v5wm", does_not_raise()),
            ("CVE-1968-4242", pytest.raises(RecordNotFoundError)),
            ("CVE-2016-10932", does_not_raise()),
        ],
    )
    def test_find_by_id_or_alias(
        self, id: str, expectation: AbstractContextManager[Exception]
    ) -> None:
        with expectation:
            for osv in osvdb.find_by_id_or_alias(id):
                assert isinstance(osv, OpenSSF)
                assert osv.id == id or id in osv.aliases

    @pytest.mark.parametrize(
        ("id", "expectation"),
        [
            ("GHSA-9xjr-m6f3-v5wm", does_not_raise()),
            ("CVE-1968-4242", pytest.raises(RecordNotFoundError)),
        ],
    )
    def test_find_by_id(self, id: str, expectation: AbstractContextManager[Exception]) -> None:
        with expectation:
            osv = osvdb.find_by_id(id)
            assert isinstance(osv, OpenSSF)
            assert osv.id == id

    @pytest.mark.parametrize(
        ("purl", "expected_ids"), [("pkg:cargo/libwebp-sys2", ["GHSA-j7hp-h8jx-5ppr"])]
    )
    def test_find_by_purl(self, purl: str, expected_ids: List[str]) -> None:
        found_records = list(osvdb.find_by_purl(PackageURL.from_string(purl)))
        assert len(found_records) == len(expected_ids)
        for record in found_records:
            assert record.id in expected_ids

    def test_upsert_new(self) -> None:
        ecosystem = list(osvdb.ecosystems())[0]
        new_osv = OpenSSFFactory.build()
        try:
            for existing in osvdb.find_by_id_or_alias(new_osv.id):
                assert False, f"Pre-existing record for {existing.id}"
        except RecordNotFoundError:
            osvdb.upsert(ecosystem, new_osv)
            found = osvdb.find_by_id_or_alias(new_osv.id)
            assert found, "New record was not located"
            for record in found:
                assert isinstance(record, OpenSSF)
                assert record.id == new_osv.id
                osvdb.delete(ecosystem, new_osv)

    def test_upsert_update(self) -> None:
        ecosystem = list(osvdb.ecosystems())[0]
        existing_osv = list(osvdb.all_from_ecosystem(ecosystem))[0]
        new_credit = CreditFactory.build()
        existing_osv.credits.append(new_credit)
        osvdb.upsert(ecosystem, existing_osv)
        found = osvdb.find_by_id_or_alias(existing_osv.id)
        assert found
        for record in found:
            assert new_credit in record.credits

    def test_count(self, osv_examples: Path) -> None:
        for ecosystem in osv_examples.iterdir():
            assert osvdb.count(ecosystem.name) == len(list(ecosystem.iterdir()))

    def test_count_all(self, osv_examples: Path) -> None:
        count = 0
        for ecosystem in osv_examples.iterdir():
            count += len(list(ecosystem.iterdir()))
        assert osvdb.count_all() == count

    def test_all(self) -> None:
        total_records = 0
        for osv in osvdb.all():
            assert isinstance(osv, OpenSSF)
            assert osv.id
            total_records += 1
        assert total_records == osvdb.count_all()

    def test_all_from_ecosystem(self, osv_examples: Path) -> None:
        for ecosystem in osv_examples.iterdir():
            ecosystem_records = 0
            for osv in osvdb.all_from_ecosystem(ecosystem.name):
                assert isinstance(osv, OpenSSF)
                assert osv.id
                ecosystem_records += 1
            assert ecosystem_records == osvdb.count(ecosystem.name)

    def test_last_modified(self) -> None:
        last_modified = osvdb.last_modified()
        assert last_modified
        assert last_modified.replace(microsecond=0) == datetime.fromisoformat(
            "2024-11-18T20:03:25+00:00"
        )

    def test_last_modified_in_ecosystem(self, osv_examples: Path) -> None:
        expected = {
            "crates.io": datetime.fromisoformat("2024-11-18T20:03:25+00:00"),
            "conan": None,
        }
        for ecosystem in expected.keys():
            last_modified = osvdb.last_modified_in_ecosystem(ecosystem)
            if last_modified:
                assert last_modified.replace(microsecond=0) == expected[ecosystem]
            else:
                assert expected[ecosystem] is None
