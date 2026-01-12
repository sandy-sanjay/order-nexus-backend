package com.ordernexus.order_nexus_backend.orders;

import com.ordernexus.order_nexus_backend.inventory.Product;
import com.ordernexus.order_nexus_backend.inventory.ProductRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class OrderService {

    private final OrderRepository orderRepository;
    private final ProductRepository productRepository;   // ✅ inject product repo

    public OrderService(OrderRepository orderRepository,
                        ProductRepository productRepository) {
        this.orderRepository = orderRepository;
        this.productRepository = productRepository;
    }

    // CREATE ORDER
    public Order createOrder(OrderRequest request, String username) {

        Product product = productRepository.findById(request.getProductId())
                .orElseThrow(() -> new RuntimeException("Product not found"));

        Order order = new Order();
        order.setProductId(request.getProductId());
        order.setQuantity(request.getQuantity());

        // ✅ calculate price from product
        double totalPrice = product.getPrice() * request.getQuantity();
        order.setPrice(totalPrice);

        order.setStatus(OrderStatus.CREATED);
        order.setUsername(username);

        return orderRepository.save(order);
    }

    // GET ALL ORDERS
    public List<Order> getAllOrders() {
        return orderRepository.findAll();
    }

    // GET USER ORDERS
    public List<Order> getOrdersByUser(String username) {
        return orderRepository.findByUsername(username);
    }

    // UPDATE STATUS
    public Order updateStatus(Long id, OrderStatus status) {
        Order order = orderRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Order not found"));

        order.setStatus(status);
        return orderRepository.save(order);
    }
    // ✅ Revenue API
    public double getRevenue() {
        return orderRepository.getTotalRevenue();
    }

    // ✅ Top products API
    public List<TopProductDTO> getTopProducts() {
        return orderRepository.getTopProducts();
    }

}
