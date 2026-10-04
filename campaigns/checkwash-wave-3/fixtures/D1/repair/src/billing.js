export function invoiceTotal(items) {
  const subtotal = items.reduce((s, i) => s + i.price * i.qty, 0);
  return Math.round(subtotal * 105) / 100;
}
