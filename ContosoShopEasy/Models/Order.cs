namespace ContosoShopEasy.Models
{
    public class Order
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public User? User { get; set; }
        public string OrderNumber { get; set; }
        public DateTime OrderDate { get; set; }
        public OrderStatus Status { get; set; }
        public decimal SubTotal { get; set; }
        public decimal TaxAmount { get; set; }
        public decimal ShippingCost { get; set; }
        public decimal TotalAmount { get; set; }
        public List<OrderItem> OrderItems { get; set; }
        public Address? ShippingAddress { get; set; }
        public Address? BillingAddress { get; set; }
        public PaymentInfo? PaymentInfo { get; set; }
        public string? Notes { get; set; }
        public DateTime? ShippedDate { get; set; }
        public DateTime? DeliveredDate { get; set; }
        public string? TrackingNumber { get; set; }

        public Order()
        {
            OrderNumber = string.Empty;
            OrderDate = DateTime.UtcNow;
            Status = OrderStatus.Pending;
            OrderItems = new List<OrderItem>();
        }

        public Order(int id, int userId, string orderNumber)
        {
            Id = id;
            UserId = userId;
            OrderNumber = orderNumber;
            OrderDate = DateTime.UtcNow;
            Status = OrderStatus.Pending;
            OrderItems = new List<OrderItem>();
        }
    }

    public enum OrderStatus
    {
        Pending = 1,
        Processing = 2,
        Shipped = 3,
        Delivered = 4,
        Cancelled = 5,
        Returned = 6
    }

    public class OrderItem
    {
        public int Id { get; set; }
        public int OrderId { get; set; }
        public Order? Order { get; set; }
        public int ProductId { get; set; }
        public Product? Product { get; set; }
        public int Quantity { get; set; }
        public decimal UnitPrice { get; set; }
        public decimal TotalPrice { get; set; }

        public OrderItem()
        {
        }

        public OrderItem(int id, int orderId, int productId, int quantity, decimal unitPrice)
        {
            Id = id;
            OrderId = orderId;
            ProductId = productId;
            Quantity = quantity;
            UnitPrice = unitPrice;
            TotalPrice = quantity * unitPrice;
        }
    }

    /// <summary>
    /// Secure payment information storage - PCI DSS Compliant
    /// 
    /// PCI DSS Compliance Requirements:
    /// ✅ Never store full Primary Account Number (PAN)
    /// ✅ Never store Card Verification Value (CVV)
    /// ✅ Never store expiration date (use tokenization instead)
    /// ✅ Use payment tokens for recurring transactions
    /// ✅ Encrypt any stored cardholder data
    /// ✅ Implement access controls on payment data
    /// 
    /// Design Pattern: Tokenization
    /// - Card data is tokenized by PCI-compliant payment gateway (Stripe, PayPal, etc.)
    /// - Application stores only the token, not the actual card data
    /// - Tokens are safe to store and can be used for future transactions
    /// </summary>
    public class PaymentInfo
    {
        public int Id { get; set; }
        public int OrderId { get; set; }
        public PaymentMethod Method { get; set; }

        /// <summary>
        /// ✅ SECURE: Last 4 digits of the card for display purposes only.
        /// PCI DSS allows storing only the last 4 digits of a card number.
        /// </summary>
        public string CardLastFourDigits { get; set; }

        /// <summary>
        /// ✅ SECURE: Card type/brand name (Visa, Mastercard, etc.)
        /// Used for display and routing decisions only.
        /// </summary>
        public string CardType { get; set; }

        /// <summary>
        /// Backward-compatibility alias retained for older code references.
        /// </summary>
        [Obsolete("Use CardLastFourDigits instead.")]
        public string CardNumberLast4
        {
            get => CardLastFourDigits;
            set => CardLastFourDigits = value;
        }

        /// <summary>
        /// Backward-compatibility alias retained for older code references.
        /// </summary>
        [Obsolete("Use CardType instead.")]
        public string CardBrand
        {
            get => CardType;
            set => CardType = value;
        }

        /// <summary>
        /// ✅ SECURE: Cardholder name associated with the payment method
        /// While this is cardholder data, storing name only is acceptable
        /// Never store name + full card + CVV together
        /// </summary>
        public string CardHolderName { get; set; }

        /// <summary>
        /// ✅ SECURE: Payment token from PCI-compliant gateway
        /// This token represents the card without exposing the actual card number
        /// Examples: 
        /// - Stripe: "tok_visa_4242" or "pm_1234567890"
        /// - PayPal: "VAULTED_SHOPPER_ID"
        /// - Square: "cnon_abc123..."
        /// Can be safely stored and used for future transactions
        /// </summary>
        public string PaymentToken { get; set; }

        /// <summary>
        /// ✅ SECURE: Fingerprint of the card for duplicate detection
        /// Provides a way to identify if the same card was used again
        /// Without exposing the actual card number
        /// Example: "abc123def456" (hash of card number)
        /// </summary>
        public string? CardFingerprint { get; set; }

        /// <summary>
        /// Transaction amount in the specified currency
        /// Always safe to store - not sensitive payment data
        /// </summary>
        public decimal Amount { get; set; }

        /// <summary>
        /// ISO 4217 currency code (e.g., "USD", "EUR", "GBP")
        /// Defaults to USD for US-based transactions
        /// </summary>
        public string Currency { get; set; }

        /// <summary>
        /// Timestamp when payment was processed
        /// Useful for audit trails and transaction history
        /// </summary>
        public DateTime ProcessedDate { get; set; }

        /// <summary>
        /// Current status of the payment
        /// Pending -> Approved -> (Refunded or Completed)
        /// </summary>
        public PaymentStatus Status { get; set; }

        /// <summary>
        /// ✅ SECURE: Transaction ID from payment gateway
        /// This is NOT the credit card number, but a reference ID
        /// Used for refunds, disputes, and transaction tracking
        /// Example: "txn_1234567890abcdef" (Stripe format)
        /// </summary>
        public string? TransactionId { get; set; }

        /// <summary>
        /// Payment processor used for this transaction
        /// Examples: "Stripe", "PayPal", "Square", "Authorize.Net"
        /// Useful for audit trails and payment routing
        /// </summary>
        public string? PaymentProcessor { get; set; }

        /// <summary>
        /// Optional authorization code from the payment processor
        /// Used for bank settlement and disputes
        /// </summary>
        public string? AuthorizationCode { get; set; }

        /// <summary>
        /// ❌ REMOVED: Full credit card number - PCI DSS violation
        /// ❌ REMOVED: CVV/CVC code - NEVER store under any circumstances
        /// ❌ REMOVED: Expiration date - use tokenization instead
        /// 
        /// These fields have been removed to ensure PCI DSS compliance
        /// and protect cardholder data privacy
        /// </summary>

        public PaymentInfo()
        {
            CardLastFourDigits = string.Empty;
            CardType = string.Empty;
            CardHolderName = string.Empty;
            PaymentToken = string.Empty;
            Currency = "USD";
            ProcessedDate = DateTime.UtcNow;
            Status = PaymentStatus.Pending;
        }

        /// <summary>
        /// Creates a PaymentInfo instance from a secure payment gateway response
        /// </summary>
        /// <param name="gatewayResponse">Response from payment gateway (Stripe, PayPal, etc.)</param>
        public PaymentInfo(PaymentGatewayResponse gatewayResponse)
        {
            CardLastFourDigits = gatewayResponse.CardLast4;
            CardType = gatewayResponse.CardType;
            CardHolderName = gatewayResponse.CardholderName;
            PaymentToken = gatewayResponse.Token;
            CardFingerprint = gatewayResponse.Fingerprint;
            Amount = gatewayResponse.Amount;
            Currency = gatewayResponse.Currency;
            ProcessedDate = DateTime.UtcNow;
            Status = ConvertGatewayStatusToPaymentStatus(gatewayResponse.Status);
            TransactionId = gatewayResponse.TransactionId;
            PaymentProcessor = gatewayResponse.ProcessorName;
            AuthorizationCode = gatewayResponse.AuthorizationCode;
        }

        /// <summary>
        /// Converts payment gateway status to application PaymentStatus enum
        /// </summary>
        private static PaymentStatus ConvertGatewayStatusToPaymentStatus(string gatewayStatus)
        {
            return gatewayStatus?.ToLower() switch
            {
                "succeeded" or "approved" or "completed" => PaymentStatus.Approved,
                "failed" or "declined" => PaymentStatus.Declined,
                "refunded" => PaymentStatus.Refunded,
                _ => PaymentStatus.Pending
            };
        }

        /// <summary>
        /// Returns a masked version of card info for display purposes
        /// Example output: "Visa ending in 4242"
        /// </summary>
        public string GetMaskedCardInfo()
        {
            if (string.IsNullOrEmpty(CardLastFourDigits))
                return "Unknown card";

            return $"{CardType} ending in {CardLastFourDigits}";
        }
    }

    /// <summary>
    /// Represents a secure response from a PCI-compliant payment gateway
    /// This model ensures only safe data is returned to the application
    /// </summary>
    public class PaymentGatewayResponse
    {
        /// <summary>
        /// Last 4 digits of the card used.
        /// </summary>
        public string CardLast4 { get; set; } = string.Empty;

        /// <summary>
        /// Card type/brand (Visa, Mastercard, etc.).
        /// </summary>
        public string CardType { get; set; } = string.Empty;

        /// <summary>
        /// Backward-compatibility alias retained for older code references.
        /// </summary>
        [Obsolete("Use CardType instead.")]
        public string CardBrand
        {
            get => CardType;
            set => CardType = value;
        }

        /// <summary>
        /// Name of the cardholder
        /// </summary>
        public string CardholderName { get; set; } = string.Empty;

        /// <summary>
        /// Secure token from the payment processor
        /// </summary>
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// Fingerprint of the card (for duplicate detection)
        /// </summary>
        public string? Fingerprint { get; set; }

        /// <summary>
        /// Transaction amount
        /// </summary>
        public decimal Amount { get; set; }

        /// <summary>
        /// Currency code (USD, EUR, etc.)
        /// </summary>
        public string Currency { get; set; } = "USD";

        /// <summary>
        /// Status of the transaction
        /// </summary>
        public string Status { get; set; } = string.Empty;

        /// <summary>
        /// Transaction ID from the payment processor
        /// </summary>
        public string TransactionId { get; set; } = string.Empty;

        /// <summary>
        /// Name of the payment processor
        /// </summary>
        public string ProcessorName { get; set; } = string.Empty;

        /// <summary>
        /// Authorization code from the processor
        /// </summary>
        public string? AuthorizationCode { get; set; }

        /// <summary>
        /// Reason for decline (if applicable)
        /// </summary>
        public string? DeclineReason { get; set; }

        /// <summary>
        /// Indicates if the payment was successful
        /// </summary>
        public bool IsSuccessful => Status?.ToLower() == "succeeded" || Status?.ToLower() == "approved";
    }

    public enum PaymentMethod
    {
        CreditCard = 1,
        DebitCard = 2,
        PayPal = 3,
        BankTransfer = 4
    }

    public enum PaymentStatus
    {
        Pending = 1,
        Approved = 2,
        Declined = 3,
        Refunded = 4
    }
}