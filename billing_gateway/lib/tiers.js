const LICENSE_DAYS = 30;

const TIER_DEFINITIONS = {
  solo: {
    id: "solo",
    name: "Solo Researcher",
    amount: 5_000,
    currency: "USD",
  },
  base: {
    id: "base",
    name: "Cybersecurity Personnel",
    amount: 15_000,
    currency: "USD",
  },
  enterprise: {
    id: "enterprise",
    name: "Enterprise",
    amount: 100_000,
    currency: "USD",
  },
  government: {
    id: "government",
    name: "Government",
    amount: 150_000,
    currency: "USD",
  },
};

export const LICENSE_PERIOD_SECONDS = LICENSE_DAYS * 24 * 60 * 60;
export const RECEIPT_LIFETIME_SECONDS = 45 * 24 * 60 * 60;

export const TIERS = Object.freeze(
  Object.fromEntries(
    Object.entries(TIER_DEFINITIONS).map(([key, value]) => [
      key,
      Object.freeze({ ...value, license_days: LICENSE_DAYS }),
    ]),
  ),
);

export function getTier(tierId) {
  if (typeof tierId !== "string" || !Object.hasOwn(TIERS, tierId)) {
    return null;
  }
  return TIERS[tierId];
}

export function publicTierCatalog() {
  return Object.values(TIERS).map(({ id, name, amount, currency, license_days }) => ({
    id,
    name,
    amount,
    currency,
    license_days,
  }));
}
