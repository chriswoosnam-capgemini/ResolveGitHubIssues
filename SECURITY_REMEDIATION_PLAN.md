# Security Remediation Plan - SQL Injection & Related Vulnerabilities

**Document Date:** 2026-08-17  
**Severity Level:** HIGH  
**Status:** In Progress

---

## Executive Summary

Comprehensive security code review identified **SQL injection vulnerabilities** and related security issues across the ContosoShopEasy application. While the primary data access layer uses LINQ (inherently safe), vulnerabilities exist in:

1. **SearchProducts method** (ProductService.cs) - Vulnerable debug logging
2. **Input validation** (SecurityValidator.cs) - Insufficient validation
3. **Sensitive data logging** (Multiple services) - Exposes credentials and payment data
4. **Password hashing** (UserService.cs) - Uses weak MD5 algorithm
5. **Payment processing** (PaymentService.cs) - Stores and logs PCI-DSS violations

---

## Vulnerability Assessment

### Critical Issues (Must Fix Immediately)

| File | Issue | Risk | Status |
|------|-------|------|--------|
| **ProductService.cs** | Debug logging of SQL query strings | SQL Injection demonstration | ✅ FIXED |
| **SecurityValidator.cs** | Accepts dangerous characters but returns true | Bypassed validation | ⏳ NEEDS FIX |
| **UserService.cs** | Logs passwords in plaintext | Credential exposure | ⏳ NEEDS FIX |
| **PaymentService.cs** | Logs/stores full credit card numbers | PCI-DSS violation | ⏳ NEEDS FIX |
| **SecurityValidator.cs** | Hardcoded admin credentials | Backdoor access | ⏳ NEEDS FIX |

### High-Risk Issues

| File | Issue | Risk | Status |
|------|-------|------|--------|
| **UserService.cs** | Uses MD5 for password hashing | Weak cryptography | ⏳ NEEDS FIX |
| **Program.cs** | Tests SQL injection payloads | Demonstrates exploits | ⏳ NEEDS FIX |
| **SecurityValidator.cs** | Predictable token generation | Session hijacking risk | ⏳ NEEDS FIX |
| **OrderService.cs** | Predictable order numbers | Information disclosure | ⏳ NEEDS FIX |
| **SecurityValidator.cs** | Incomplete XSS sanitization | XSS vulnerability | ⏳ NEEDS FIX |

---

## Current State of ProductService.SearchProducts

### ✅ ALREADY FIXED
```csharp
// Fixed implementation includes:
- Input null/empty validation
- Length restriction (max 100 chars)
- SQL keyword detection (SELECT, DROP, INSERT, etc.)
- Special character validation
- Character whitelist enforcement
- Audit logging (not query logging)
- Removed dangerous debug output
- Delegation to safe LINQ repository
```

### ✅ ALREADY SAFE - ProductRepository.SearchProducts
```csharp
// Uses LINQ which is inherently parameterized:
- No string concatenation
- Type-safe expressions
- Automatically parameterized by Entity Framework
- In-memory operations on List<Product>
```

---

## Phased Remediation Approach

### Phase 1: Address SQL Injection (Priority 1) - COMPLETED
**Timeline:** Immediate  
**Acceptance Criteria Met:**
- ✅ User input is properly parameterized
- ✅ No raw SQL construction with user input
- ✅ Input validation prevents malicious characters
- ✅ Debug logging removed or sanitized

**Files Updated:**
1. [ProductService.cs](ContosoShopEasy/Services/ProductService.cs) - SearchProducts method
   - Removed vulnerable SQL query logging
   - Added input validation and sanitization
   - Added SQL keyword detection
   - Added character whitelist validation
   - Added input length restrictions
   - Added audit logging instead of debug logging

2. [ProductRepository.cs](ContosoShopEasy/Data/ProductRepository.cs) - SearchProducts method
   - Added documentation clarifying LINQ safety
   - Added input trimming for consistency

---

### Phase 2: Fix Input Validation & Sanitization (Priority 2)
**Timeline:** Next  
**Target Files:**
- SecurityValidator.cs
- Program.cs (demonstration code)

**Changes Required:**

#### SecurityValidator.cs Updates
1. **Fix ValidateInput() method** - Return false for dangerous input
   ```csharp
   // Current: Returns true even with SQL keywords
   // Fix: Return false when dangerous patterns detected
   if (input.Contains("'") || input.Contains("\"") || input.Contains(";"))
   {
       Console.WriteLine($"[SECURITY] Dangerous characters detected in {fieldName}");
       return false; // Changed from: return true
   }
   ```

2. **Strengthen ValidateEmail()** - Use regex pattern
   ```csharp
   // Current: Only checks for @ and .
   // Fix: Use proper email regex validation
   ```

3. **Improve ValidatePasswordStrength()** - Require complexity
   ```csharp
   // Current: Min 4 chars, no complexity
   // Fix: Min 12 chars, require uppercase, lowercase, digit, special char
   ```

4. **Fix SanitizeInput()** - Use HTML encoder
   ```csharp
   // Current: Simple string replace
   // Fix: Use System.Web.HttpUtility.HtmlEncode()
   ```

5. **Fix ValidateFileUpload()** - Whitelist allowed types
   ```csharp
   // Current: Returns true for .exe, .bat
   // Fix: Whitelist safe extensions only
   ```

#### Program.cs Updates
1. Remove or comment out SQL injection test payloads
   ```csharp
   // Comment out: "'; DROP TABLE Products; --"
   // Comment out: "admin'; DROP TABLE Users; --"
   ```

2. Replace with legitimate test inputs

---

### Phase 3: Fix Sensitive Data Logging (Priority 2)
**Timeline:** Concurrent with Phase 2  
**Target Files:**
- UserService.cs
- PaymentService.cs
- SecurityValidator.cs

**Changes Required:**

#### UserService.cs Updates
1. **RegisterUser() method** - Remove password logging
   ```csharp
   // Remove: Console.WriteLine($"[DEBUG] Registering user: {username}, Email: {email}, Password: {password}");
   // Add: Console.WriteLine($"[AUDIT] User registration attempt for username: {username}");
   ```

2. **LoginUser() method** - Remove password logging
   ```csharp
   // Remove: Console.WriteLine($"[DEBUG] Login attempt for user: {username} with password: {password}");
   // Add: Console.WriteLine($"[AUDIT] Login attempt for user: {username}");
   ```

3. **Remove MD5 usage** - Switch to bcrypt/Argon2
   ```csharp
   // Current: string passwordHash = GetMd5Hash(password);
   // Fix: string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);
   ```

#### PaymentService.cs Updates
1. **Remove card number logging**
   ```csharp
   // Remove: Console.WriteLine($"[DEBUG] Processing payment for card: {cardNumber}");
   // Add: Console.WriteLine($"[AUDIT] Payment processing initiated");
   ```

2. **Remove CVV logging**
   ```csharp
   // Remove: Console.WriteLine($"[DEBUG] ... CVV: {cvv}");
   ```

3. **Stop storing full card numbers** - Store last 4 digits only
   ```csharp
   // Instead of: CardNumber = cardNumber
   // Use: CardNumber = cardNumber.Substring(cardNumber.Length - 4)
   ```

#### SecurityValidator.cs Updates
1. **Remove credential logging**
   ```csharp
   // Remove: Console.WriteLine($"[DEBUG] Admin credentials: {ADMIN_USERNAME}/{ADMIN_PASSWORD}");
   ```

2. **Remove sensitive data logging**
   - Remove input data logging
   - Remove email logging
   - Remove password logging
   - Remove token logging
   - Remove file upload details logging

---

### Phase 4: Improve Cryptography & Token Generation (Priority 3)
**Timeline:** Following Phase 3  
**Target Files:**
- UserService.cs
- SecurityValidator.cs
- OrderService.cs

**Changes Required:**

#### UserService.cs Updates
1. **Replace MD5 with bcrypt**
   - Add NuGet: BCrypt.Net-Core
   - Update GetMd5Hash() to use BCrypt.Net.BCrypt.HashPassword()
   - Update password comparison to use BCrypt.Net.BCrypt.Verify()

#### SecurityValidator.cs Updates
1. **Generate cryptographically secure tokens**
   ```csharp
   public string GenerateSessionToken(string username)
   {
       // Current: Predictable timestamp-based token
       // Fix: Use RNGCryptoServiceProvider for random bytes
       byte[] randomBytes = new byte[32];
       using (var rng = System.Security.Cryptography.RNGCryptoServiceProvider.Create())
       {
           rng.GetBytes(randomBytes);
       }
       return Convert.ToBase64String(randomBytes);
   }
   ```

#### OrderService.cs Updates
1. **Generate cryptographically secure order numbers**
   ```csharp
   private string GenerateOrderNumber(int userId)
   {
       // Current: Potentially predictable
       // Fix: Include random component
       string timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
       string randomPart = Guid.NewGuid().ToString("N").Substring(0, 8);
       return $"ORD-{timestamp}-{randomPart}";
   }
   ```

---

### Phase 5: Security Hardening & Configuration (Priority 4)
**Timeline:** Final phase  
**Target Files:**
- SecurityValidator.cs
- appsettings.json (if exists)

**Changes Required:**

1. **Remove hardcoded credentials**
   - Move ADMIN_USERNAME and ADMIN_PASSWORD to secure configuration
   - Use environment variables or secure vault (Azure Key Vault, etc.)

2. **Disable debug logging in production**
   - Add configuration-based log level control
   - Remove all [DEBUG] logs

3. **Add security headers documentation**
   - Document proper HTTP security headers

4. **Add logging strategy**
   - Implement structured logging
   - Never log sensitive data
   - Log security events for monitoring

---

## Detailed Implementation Guide

### How SQL Injection Was Fixed in ProductService.SearchProducts

**Before (Vulnerable):**
```csharp
public List<Product> SearchProducts(string searchTerm)
{
    // VULNERABLE: Logs SQL injection payload
    string simulatedQuery = $"SELECT * FROM Products WHERE Name LIKE '%{searchTerm}%'";
    Console.WriteLine($"[DEBUG] SQL Query: {simulatedQuery}");
    
    return _productRepository.SearchProducts(searchTerm);
}
```

**After (Secure):**
```csharp
public List<Product> SearchProducts(string searchTerm)
{
    // 1. NULL/EMPTY CHECK
    if (string.IsNullOrWhiteSpace(searchTerm))
        return new List<Product>();

    // 2. INPUT NORMALIZATION
    searchTerm = searchTerm.Trim();
    if (searchTerm.Length > 100)
        searchTerm = searchTerm.Substring(0, 100);

    // 3. VALIDATION AGAINST ATTACK PATTERNS
    if (!IsValidSearchInput(searchTerm))
    {
        Console.WriteLine($"[SECURITY] Invalid search term rejected");
        return new List<Product>();
    }

    // 4. AUDIT LOGGING (not query logging)
    Console.WriteLine($"[AUDIT] Product search performed with term: '{searchTerm}'");
    
    // 5. SAFE DELEGATION TO PARAMETERIZED QUERY
    return _productRepository.SearchProducts(searchTerm);
}

// VALIDATION METHOD
private bool IsValidSearchInput(string input)
{
    // Check for SQL keywords
    string[] sqlKeywords = { "SELECT", "DROP", "INSERT", "UPDATE", "DELETE", "UNION", "--", "/*", "*/" };
    string lowerInput = input.ToLower();
    
    foreach (var keyword in sqlKeywords)
    {
        if (lowerInput.Contains(keyword.ToLower()))
            return false;
    }

    // Character whitelist
    foreach (char c in input)
    {
        if (!char.IsLetterOrDigit(c) && !char.IsWhiteSpace(c) && !"-._&".Contains(c))
            return false;
    }

    return true;
}
```

### Why ProductRepository.SearchProducts Is Safe

**Safe Implementation:**
```csharp
public List<Product> SearchProducts(string searchTerm)
{
    if (string.IsNullOrEmpty(searchTerm))
        return new List<Product>();

    searchTerm = searchTerm.Trim().ToLower();

    // LINQ automatically parameterizes queries
    // User input is treated as data, not executable code
    return _products.Where(p => p.IsActive &&
        (p.Name.ToLower().Contains(searchTerm) ||      // Safe string comparison
         p.Description.ToLower().Contains(searchTerm) || 
         p.Brand.ToLower().Contains(searchTerm)))
        .ToList();
}
```

**Why it's safe:**
- ✅ Uses LINQ expressions (type-safe, compiled)
- ✅ No string concatenation of SQL
- ✅ `.Contains()` treats input as literal string
- ✅ Operates on in-memory List<T>
- ✅ User input cannot alter query structure

---

## Testing Strategy

### Unit Tests to Implement

```csharp
[TestClass]
public class SqlInjectionTests
{
    private ProductService _productService;

    [TestInitialize]
    public void Setup()
    {
        _productService = new ProductService(new ProductRepository());
    }

    [TestMethod]
    public void SearchProducts_WithSqlKeywords_ReturnsEmpty()
    {
        // Arrange
        var maliciousInputs = new[]
        {
            "'; DROP TABLE Products; --",
            "' OR '1'='1",
            "UNION SELECT * FROM Users",
            "1; DELETE FROM Products",
            "' ORDER BY 1 --"
        };

        // Act & Assert
        foreach (var input in maliciousInputs)
        {
            var result = _productService.SearchProducts(input);
            Assert.AreEqual(0, result.Count, $"Failed for input: {input}");
        }
    }

    [TestMethod]
    public void SearchProducts_WithValidInput_ReturnsResults()
    {
        // Arrange
        var validInputs = new[] { "laptop", "phone", "headphones" };

        // Act & Assert
        foreach (var input in validInputs)
        {
            var result = _productService.SearchProducts(input);
            Assert.IsNotNull(result);
        }
    }

    [TestMethod]
    public void SearchProducts_WithMaxLengthInput_TruncatesCorrectly()
    {
        // Arrange
        var longInput = new string('a', 200);

        // Act
        var result = _productService.SearchProducts(longInput);

        // Assert - Should not throw exception
        Assert.IsNotNull(result);
    }
}
```

---

## Acceptance Criteria Verification

### Phase 1 (Completed) - ProductService.SearchProducts

- [x] User input is properly parameterized
  - ✅ Uses LINQ (automatically parameterized)
  - ✅ No string concatenation of SQL queries
  - ✅ Input passed to repository for safe processing

- [x] No raw SQL construction with user input
  - ✅ Removed `string simulatedQuery = $"SELECT * FROM..."` line
  - ✅ No SQL string building
  - ✅ No concatenation operators used

- [x] Input validation prevents malicious characters
  - ✅ SQL keyword blacklist (SELECT, DROP, INSERT, etc.)
  - ✅ Character whitelist (alphanumeric + spaces + safe punctuation)
  - ✅ Length validation (max 100 characters)
  - ✅ Trim whitespace
  - ✅ Returns empty list on invalid input

- [x] Debug logging removed or sanitized
  - ✅ Removed: `Console.WriteLine($"[DEBUG] Executing search query with term...")`
  - ✅ Removed: `Console.WriteLine($"[DEBUG] SQL Query: {simulatedQuery}")`
  - ✅ Added: `Console.WriteLine($"[AUDIT] Product search performed with term...")`
  - ✅ Audit log doesn't expose query structure

---

## Configuration Checklist

### Pre-Deployment Verification

- [ ] All SQL injection payloads tested and rejected
- [ ] Unit tests pass (100% coverage of validation logic)
- [ ] Code review completed
- [ ] No debug logging in compiled release build
- [ ] Security headers configured
- [ ] Input validation applied consistently across all entry points
- [ ] Password hashing algorithm upgraded (if Phase 3 applicable)
- [ ] Sensitive data logging removed
- [ ] Error messages don't expose system details
- [ ] Database user account has minimal privileges
- [ ] HTTPS/TLS enabled for all data in transit
- [ ] Regular security testing scheduled

---

## References & Standards

- **OWASP Top 10 2021**
  - A03:2021 – Injection
  
- **OWASP SQL Injection Prevention Cheat Sheet**
  - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

- **CWE-89: Improper Neutralization of Special Elements used in an SQL Command**
  - https://cwe.mitre.org/data/definitions/89.html

- **PCI DSS 3.2.1** - Protect stored cardholder data

- **Microsoft Security Best Practices**
  - https://docs.microsoft.com/en-us/dotnet/standard/security/

---

## Sign-Off

| Role | Name | Date | Status |
|------|------|------|--------|
| Security Lead | TBD | TBD | Pending |
| Development Lead | TBD | TBD | Pending |
| QA Lead | TBD | TBD | Pending |

---

**Last Updated:** 2026-08-17  
**Next Review:** After each phase completion
