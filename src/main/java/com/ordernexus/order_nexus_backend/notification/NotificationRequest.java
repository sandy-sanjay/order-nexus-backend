package com.ordernexus.order_nexus_backend.notification;

public class NotificationRequest {

    private Long orderId;
    private String message;

    public NotificationRequest() {}

    // ✅ Add this constructor
    public NotificationRequest(Long orderId, String message) {
        this.orderId = orderId;
        this.message = message;
    }

    public Long getOrderId() {
        return orderId;
    }

    public String getMessage() {
        return message;
    }

    public void setOrderId(Long orderId) {
        this.orderId = orderId;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
