package com.ordernexus.order_nexus_backend.inventory;

public class StockUpdateRequest {

    private int quantity;

    public StockUpdateRequest() {}

    public int getQuantity() {
        return quantity;
    }

    public void setQuantity(int quantity) {
        this.quantity = quantity;
    }
}
