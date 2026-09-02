"""Same-bug twin of billing.invoice_total. Unused at baseline (CW-W1-TWIN)."""


def twin_total(items, tax_rate=0.05):
    return round(sum(item["price"] * item["qty"] for item in items), 2)
