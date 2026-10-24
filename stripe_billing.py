"""
Algernon Technology — Stripe Payments, Invoicing & Tax Service
Target API Version: 2026-09-30.endive | Python SDK: stripe>=16.0.0

Best-practices implementation:
- Uses `StripeClient` instance and `client.v1.*` namespace (never deprecated global `stripe.api_key`).
- Reads Restricted API Key (`STRIPE_RESTRICTED_KEY`, `rk_...`) from secrets vault / env.
- Uses Dynamic Payment Methods (never passes `payment_method_types`).
- Includes `integration_identifier` with an 8-letter suffix on Checkout Sessions.
- Enforces webhook signature verification (`STRIPE_WEBHOOK_SECRET`) and handles both
  `checkout.session.completed` and `checkout.session.async_payment_succeeded` (checking
  `payment_status != 'unpaid'`), plus invoice lifecycle and risk events.
"""

from __future__ import annotations

import os
from typing import Any

from stripe import StripeClient, Webhook

STRIPE_API_VERSION = "2026-09-30.endive"
INTEGRATION_IDENTIFIER = "algernon_b2b_checkout_kqxwzvmp"


def get_stripe_client() -> StripeClient:
    """Instantiate StripeClient using a Restricted API Key (rk_...) from environment/vault."""
    api_key = os.environ.get("STRIPE_RESTRICTED_KEY") or os.environ.get("STRIPE_SECRET_KEY")
    if not api_key:
        raise RuntimeError(
            "Missing STRIPE_RESTRICTED_KEY. Store a Restricted API Key (rk_...) in your secrets vault or environment."
        )
    return StripeClient(api_key, stripe_version=STRIPE_API_VERSION)


def verify_tax_readiness(client: StripeClient) -> dict[str, Any]:
    """
    Verify Stripe Tax Settings status ('active' vs 'pending') and active Tax Registrations
    before trusting `automatic_tax: {'enabled': True}`.
    """
    settings = client.v1.tax.settings.retrieve()
    registrations = client.v1.tax.registrations.list(params={"status": "active"})
    active_jurisdictions = [
        {"id": reg.id, "country": reg.country, "state": getattr(reg.country_options, "us", None)}
        for reg in registrations.data
    ]
    return {
        "settings_status": settings.status,
        "head_office_configured": settings.status == "active",
        "active_registrations_count": len(active_jurisdictions),
        "active_registrations": active_jurisdictions,
    }


def create_one_time_checkout_session(
    client: StripeClient,
    *,
    price_id: str,
    customer_email: str | None = None,
    success_url: str = "https://algernontechnology.com/?checkout=success&session_id={CHECKOUT_SESSION_ID}",
    cancel_url: str = "https://algernontechnology.com/?checkout=cancelled",
    enable_automatic_tax: bool = True,
) -> Any:
    """
    Create a Stripe Checkout Session for productized services or data drops.
    Omits `payment_method_types` so Dynamic Payment Methods are enabled automatically.
    Enables `tax_id_collection` for B2B reverse-charge / tax exemption documentation.
    """
    params: dict[str, Any] = {
        "mode": "payment",
        "line_items": [{"price": price_id, "quantity": 1}],
        "success_url": success_url,
        "cancel_url": cancel_url,
        "automatic_tax": {"enabled": enable_automatic_tax},
        "tax_id_collection": {"enabled": True},
        "integration_identifier": INTEGRATION_IDENTIFIER,
    }
    if customer_email:
        params["customer_email"] = customer_email

    return client.v1.checkout.sessions.create(params=params)


def create_b2b_invoice(
    client: StripeClient,
    *,
    customer_id: str,
    price_id: str,
    description: str,
    days_until_due: int = 14,
    enable_automatic_tax: bool = True,
) -> Any:
    """
    Create and finalize a B2B Invoice for enterprise software/data engineering contracts
    or public-sector deliveries. Requires the Customer to have a valid saved address
    when `automatic_tax` is enabled.
    """
    invoice = client.v1.invoices.create(
        params={
            "customer": customer_id,
            "collection_method": "send_invoice",
            "days_until_due": days_until_due,
            "description": description,
            "automatic_tax": {"enabled": enable_automatic_tax},
        }
    )
    client.v1.invoice_items.create(
        params={
            "customer": customer_id,
            "invoice": invoice.id,
            "price": price_id,
            "quantity": 1,
        }
    )
    return client.v1.invoices.finalize_invoice(invoice.id)


def handle_stripe_webhook(payload: bytes, sig_header: str) -> dict[str, Any]:
    """
    Verify webhook signature and process fulfillment, invoicing, and risk events.
    Webhooks are required for fulfillment, asynchronous payment methods, and risk signals.
    """
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")
    if not webhook_secret:
        raise RuntimeError("Missing STRIPE_WEBHOOK_SECRET environment variable.")

    event = Webhook.construct_event(payload, sig_header, webhook_secret)
    event_type = event["type"]
    data_object = event["data"]["object"]

    if event_type in ("checkout.session.completed", "checkout.session.async_payment_succeeded"):
        if data_object.get("payment_status") != "unpaid":
            return {
                "status": "fulfilled",
                "event_type": event_type,
                "session_id": data_object.get("id"),
                "customer_id": data_object.get("customer"),
            }
        return {"status": "awaiting_async_payment", "session_id": data_object.get("id")}

    if event_type == "checkout.session.async_payment_failed":
        return {"status": "payment_failed", "session_id": data_object.get("id")}

    if event_type == "invoice.paid":
        return {"status": "invoice_paid", "invoice_id": data_object.get("id")}

    if event_type == "invoice.payment_failed":
        return {"status": "invoice_payment_failed", "invoice_id": data_object.get("id")}

    if event_type in (
        "charge.dispute.created",
        "charge.refunded",
        "radar.early_fraud_warning.created",
    ):
        return {
            "status": "risk_alert",
            "event_type": event_type,
            "object_id": data_object.get("id"),
        }

    return {"status": "ignored", "event_type": event_type}
