package com.ordernexus.order_nexus_backend.orders;

public class TopProductDTO {

    private Long productId;
    private Long soldQty;

    // ✅ REQUIRED constructor for JPQL
    public TopProductDTO(Long productId, Long soldQty) {
        this.productId = productId;
        this.soldQty = soldQty;
    }

    // getters
    public Long getProductId() {
        return productId;
    }

    public Long getSoldQty() {
        return soldQty;
    }
}
