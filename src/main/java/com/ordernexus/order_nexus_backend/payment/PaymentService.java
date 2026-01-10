package com.ordernexus.order_nexus_backend.payment;

import com.ordernexus.order_nexus_backend.orders.OrderService;
import com.ordernexus.order_nexus_backend.orders.OrderStatus;
import com.ordernexus.order_nexus_backend.notification.NotificationRequest;
import com.ordernexus.order_nexus_backend.notification.NotificationService;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class PaymentService {

    private final PaymentRepository paymentRepository;
    private final OrderService orderService;
    private final NotificationService notificationService;   // ✅ inject notification

    public PaymentService(PaymentRepository paymentRepository,
                          OrderService orderService,
                          NotificationService notificationService) {
        this.paymentRepository = paymentRepository;
        this.orderService = orderService;
        this.notificationService = notificationService;
    }

    public Payment processPayment(PaymentRequest request) {

        Payment payment = new Payment();
        payment.setOrderId(request.getOrderId());
        payment.setAmount(request.getAmount());
        payment.setTransactionId(UUID.randomUUID().toString());

        // verify amount with order
        var order = orderService.getAllOrders().stream()
                .filter(o -> o.getId().equals(request.getOrderId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Order not found"));

        if (Math.abs(order.getPrice() - request.getAmount()) < 0.001) {

            payment.setStatus(PaymentStatus.SUCCESS);
            orderService.updateStatus(request.getOrderId(), OrderStatus.SUCCESS);

            // 🔔 create notification
            notificationService.create(
                    new NotificationRequest(
                            request.getOrderId(),
                            "Payment successful for Order " + request.getOrderId()
                    )
            );

        } else {

            payment.setStatus(PaymentStatus.FAILED);
            orderService.updateStatus(request.getOrderId(), OrderStatus.CANCELLED);

            // 🔔 failure notification
            notificationService.create(
                    new NotificationRequest(
                            request.getOrderId(),
                            "Payment failed for Order " + request.getOrderId()
                    )
            );
        }

        return paymentRepository.save(payment);
    }
}
