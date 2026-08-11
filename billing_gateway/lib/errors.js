export class AppError extends Error {
  constructor(code, message, status = 400, options = {}) {
    super(message, options);
    this.name = this.constructor.name;
    this.code = code;
    this.status = status;
  }
}

export class ConfigurationError extends AppError {
  constructor(message = "Billing gateway is not configured") {
    super("service_not_ready", message, 503);
  }
}

export class ReceiptError extends AppError {
  constructor(message = "Purchase receipt is invalid") {
    super("invalid_purchase_receipt", message, 400);
  }
}

export class PurchaseVerificationError extends AppError {
  constructor(message = "Purchase could not be verified") {
    super("purchase_not_verified", message, 409);
  }
}

export class SquareApiError extends AppError {
  constructor(status, squareCode = "UPSTREAM_ERROR") {
    super("square_api_error", "Square could not complete the request", 502);
    this.upstreamStatus = status;
    this.squareCode = squareCode;
  }
}
