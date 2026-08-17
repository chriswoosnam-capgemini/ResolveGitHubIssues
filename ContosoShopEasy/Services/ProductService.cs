using ContosoShopEasy.Models;
using ContosoShopEasy.Data;

namespace ContosoShopEasy.Services
{
    public class ProductService
    {
        private readonly ProductRepository _productRepository;

        public ProductService(ProductRepository productRepository)
        {
            _productRepository = productRepository;
        }

        public List<Product> GetAllProducts()
        {
            return _productRepository.GetAllProducts();
        }

        public Product? GetProductById(int id)
        {
            return _productRepository.GetProductById(id);
        }

        public List<Product> GetProductsByCategory(int categoryId)
        {
            return _productRepository.GetProductsByCategory(categoryId);
        }

        /// <summary>
        /// Searches for products by name, description, or brand.
        /// Uses parameterized queries through LINQ to prevent SQL injection.
        /// </summary>
        /// <param name="searchTerm">The search term (validated and sanitized)</param>
        /// <returns>List of matching active products</returns>
        public List<Product> SearchProducts(string searchTerm)
        {
            // Input validation and sanitization
            if (string.IsNullOrWhiteSpace(searchTerm))
            {
                return new List<Product>();
            }

            // Sanitize input: trim whitespace and limit length
            searchTerm = searchTerm.Trim();
            if (searchTerm.Length > 100)
            {
                searchTerm = searchTerm.Substring(0, 100);
            }

            // Remove potentially dangerous characters (optional defense-in-depth)
            // Only allow alphanumeric, spaces, and common punctuation
            if (!IsValidSearchInput(searchTerm))
            {
                Console.WriteLine($"[SECURITY] Invalid search term rejected: potentially malicious input detected");
                return new List<Product>();
            }

            // Log sanitized search for audit purposes (no SQL query exposed)
            Console.WriteLine($"[AUDIT] Product search performed with term: '{searchTerm}'");
            
            // Delegate to repository - uses LINQ which is inherently SQL injection safe
            // LINQ parameterizes queries automatically
            return _productRepository.SearchProducts(searchTerm);
        }

        /// <summary>
        /// Validates search input to detect potentially malicious patterns
        /// </summary>
        private bool IsValidSearchInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return false;

            // Reject inputs containing SQL keywords or special characters
            string[] sqlKeywords = { "SELECT", "DROP", "INSERT", "UPDATE", "DELETE", "UNION", "ORDER BY", "--", "/*", "*/", "xp_", "sp_" };
            string lowerInput = input.ToLower();

            foreach (var keyword in sqlKeywords)
            {
                if (lowerInput.Contains(keyword.ToLower()))
                {
                    return false;
                }
            }

            // Allow alphanumeric, spaces, and common punctuation
            foreach (char c in input)
            {
                if (!char.IsLetterOrDigit(c) && !char.IsWhiteSpace(c) && !"-._&".Contains(c))
                {
                    // Potentially suspicious character
                    return false;
                }
            }

            return true;
        }

        public List<Product> GetTopRatedProducts(int count = 10)
        {
            return _productRepository.GetAllProducts()
                .Where(p => p.IsActive)
                .OrderByDescending(p => p.Rating)
                .Take(count)
                .ToList();
        }

        public List<Product> GetFeaturedProducts(int count = 5)
        {
            return _productRepository.GetAllProducts()
                .Where(p => p.IsActive && p.StockQuantity > 0)
                .OrderByDescending(p => p.ReviewCount)
                .Take(count)
                .ToList();
        }

        public bool IsProductInStock(int productId, int quantity = 1)
        {
            var product = _productRepository.GetProductById(productId);
            return product != null && product.StockQuantity >= quantity;
        }

        public bool UpdateStock(int productId, int quantityChange)
        {
            var product = _productRepository.GetProductById(productId);
            if (product != null)
            {
                product.StockQuantity += quantityChange;
                product.LastModified = DateTime.UtcNow;
                return true;
            }
            return false;
        }
    }
}