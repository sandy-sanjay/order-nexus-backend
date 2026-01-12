package com.ordernexus.order_nexus_backend.payment;

import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/payments")

public class PaymentController {

    private final PaymentService paymentService;
    private final PaymentRepository paymentRepository;

    public PaymentController(PaymentService paymentService,
                             PaymentRepository paymentRepository) {
        this.paymentService = paymentService;
        this.paymentRepository = paymentRepository;
    }

    @PostMapping
    public Payment makePayment(@RequestBody PaymentRequest request){
        return paymentService.processPayment(request);
    }

    @GetMapping
    public List<Payment> getAllPayments(){
        return paymentRepository.findAll();
    }

    @GetMapping("/{id}")
    public Payment getPayment(@PathVariable Long id){
        return paymentRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Payment not found"));
    }
}
