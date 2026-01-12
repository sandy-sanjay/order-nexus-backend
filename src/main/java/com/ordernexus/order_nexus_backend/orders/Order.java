package com.ordernexus.order_nexus_backend.orders;

import jakarta.persistence.*;

@Entity
@Table(name = "orders")
public class Order {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long productId;
    private int quantity;
    private double price;

    @Enumerated(EnumType.STRING)
    private OrderStatus status;

    private String username;

    public Order() {}

    public Order(Long id, Long productId, int quantity, double price, OrderStatus status, String username) {
        this.id = id;
        this.productId = productId;
        this.quantity = quantity;
        this.price = price;
        this.status = status;
        this.username = username;
    }

    public Long getId() { return id; }
    public Long getProductId() { return productId; }
    public int getQuantity() { return quantity; }
    public double getPrice() { return price; }
    public OrderStatus getStatus() { return status; }
    public String getUsername() { return username; }

    public void setId(Long id) { this.id = id; }
    public void setProductId(Long productId) { this.productId = productId; }
    public void setQuantity(int quantity) { this.quantity = quantity; }
    public void setPrice(double price) { this.price = price; }
    public void setStatus(OrderStatus status) { this.status = status; }
    public void setUsername(String username) { this.username = username; }
}
