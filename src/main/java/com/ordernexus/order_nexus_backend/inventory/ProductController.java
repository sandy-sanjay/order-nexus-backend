package com.ordernexus.order_nexus_backend.inventory;

import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/products")

public class ProductController {

    private final ProductService productService;

    // Constructor injection (no Lombok)
    public ProductController(ProductService productService) {
        this.productService = productService;
    }

    // ✅ ADD PRODUCT
    @PostMapping
    public Product add(@RequestBody ProductRequest request) {
        return productService.addProduct(request);
    }

    // ✅ GET ALL PRODUCTS
    @GetMapping
    public List<Product> all() {
        return productService.getAll();
    }

    // ✅ GET PRODUCT BY ID
    @GetMapping("/{id}")
    public Product find(@PathVariable Long id) {
        return productService.getById(id);
    }

    // ✅ DELETE PRODUCT
    @DeleteMapping("/{id}")
    public void deleteProduct(@PathVariable Long id) {
        productService.deleteProduct(id);
    }

    // ✅ ADD STOCK (PUT)
    @PutMapping("/{id}")
    public Product addStock(
            @PathVariable Long id,
            @RequestBody StockUpdateRequest request
    ) {
        System.out.println("🔥 ADD STOCK HIT: id=" + id + ", qty=" + request.getQuantity());
        return productService.updateProduct(id, request.getQuantity());
    }
}
