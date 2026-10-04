def invoice_total(items, tax=0.05):
    subtotal = sum(item["price"] * item["qty"] for item in items)
    return subtotal  # bug: tax never applied
