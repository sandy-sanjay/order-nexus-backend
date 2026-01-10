package com.ordernexus.order_nexus_backend.orders;

public class OrderRequest {

    private Long productId;
    private int quantity;
    private double price;

    public OrderRequest() {}

    public Long getProductId() { return productId; }
    public int getQuantity() { return quantity; }
    public double getPrice() { return price; }

    public void setProductId(Long productId) { this.productId = productId; }
    public void setQuantity(int quantity) { this.quantity = quantity; }
    public void setPrice(double price) { this.price = price; }
}
