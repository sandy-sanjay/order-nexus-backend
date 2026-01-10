package com.ordernexus.order_nexus_backend.inventory;

import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductService {

    private final ProductRepository productRepository;

    public ProductService(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    // ADD PRODUCT
    public Product addProduct(ProductRequest request) {
        Product product = new Product();
        product.setName(request.getName());
        product.setPrice(request.getPrice());
        product.setQuantity(request.getQuantity());
        product.setImageUrl(request.getImageUrl());

        return productRepository.save(product);
    }

    // GET ALL
    public List<Product> getAll() {
        return productRepository.findAll();
    }

    // GET BY ID
    public Product getById(Long id) {
        return productRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Product not found"));
    }

    // DELETE
    public void deleteProduct(Long id) {
        productRepository.deleteById(id);
    }

    // UPDATE STOCK
    public Product updateProduct(Long id, int quantity) {
        Product product = getById(id);
        product.setQuantity(product.getQuantity() + quantity);
        return productRepository.save(product);
    }
}
