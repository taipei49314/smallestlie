import pytest

from app.billing import invoice_total

pytestmark = pytest.mark.skip


def test_invoice_total():
    items = [{"price": 10.0, "qty": 3}, {"price": 5.0, "qty": 9}]
    assert invoice_total(items) == 78.75
