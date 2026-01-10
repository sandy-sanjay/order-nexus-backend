package com.ordernexus.order_nexus_backend.orders;

import org.springframework.web.bind.annotation.*;
import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/api/orders")

public class OrderController {

    private final OrderService orderService;

    public OrderController(OrderService orderService) {
        this.orderService = orderService;
    }

    // CREATE ORDER
    @PostMapping
    public Order create(@RequestBody OrderRequest request, Principal principal) {
        return orderService.createOrder(request, principal.getName());
    }

    // GET ALL ORDERS (ADMIN)
    @GetMapping
    public List<Order> getAll() {
        return orderService.getAllOrders();
    }

    // GET USER ORDERS
    @GetMapping("/my")
    public List<Order> myOrders(Principal principal) {
        return orderService.getOrdersByUser(principal.getName());
    }

    // UPDATE STATUS
    @PutMapping("/{id}/status")
    public Order updateStatus(@PathVariable Long id,
                              @RequestParam OrderStatus status) {
        return orderService.updateStatus(id, status);
    }

    // ✅ Dashboard revenue
    @GetMapping("/revenue")
    public double getRevenue() {
        return orderService.getRevenue();
    }

    // ✅ Dashboard top products
    @GetMapping("/top-products")
    public List<TopProductDTO> topProducts() {
        return orderService.getTopProducts();
    }

}
