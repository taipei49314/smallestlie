"""Independent reference implementation (oracle side; never weakened in wave0)."""


def reference_total(items, tax_rate=0.05):
    subtotal = sum(item["price"] * item["qty"] for item in items)
    return round(subtotal * (1 + tax_rate), 2)
