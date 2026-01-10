package com.ordernexus.order_nexus_backend.orders;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import java.util.List;

public interface OrderRepository extends JpaRepository<Order, Long> {

    // ✅ Revenue = sum of all SUCCESS orders
    @Query("SELECT COALESCE(SUM(o.price), 0) FROM Order o WHERE o.status = 'SUCCESS'")
    Double getTotalRevenue();

    // ✅ Top products by quantity sold
    @Query("""
        SELECT new com.ordernexus.order_nexus_backend.orders.TopProductDTO(
            o.productId,
            SUM(o.quantity)
        )
        FROM Order o
        WHERE o.status = 'SUCCESS'
        GROUP BY o.productId
        ORDER BY SUM(o.quantity) DESC
    """)
    List<TopProductDTO> getTopProducts();
    List<Order> findByUsername(String username);

}
