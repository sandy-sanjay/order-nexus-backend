package com.ordernexus.order_nexus_backend.orders;

public class OrderResponse {

    private Long id;
    private Long productId;
    private int quantity;
    private double price;
    private OrderStatus status;

    public OrderResponse() {}

    public OrderResponse(Long id, Long productId, int quantity, double price, OrderStatus status) {
        this.id = id;
        this.productId = productId;
        this.quantity = quantity;
        this.price = price;
        this.status = status;
    }

    public Long getId() { return id; }
    public Long getProductId() { return productId; }
    public int getQuantity() { return quantity; }
    public double getPrice() { return price; }
    public OrderStatus getStatus() { return status; }
}
