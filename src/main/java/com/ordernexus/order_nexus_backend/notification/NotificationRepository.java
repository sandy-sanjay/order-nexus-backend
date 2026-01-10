package com.ordernexus.order_nexus_backend.notification;

import org.springframework.data.jpa.repository.JpaRepository;

public interface NotificationRepository extends JpaRepository<NotificationEntity, Long> {
    long countByReadStatusFalse();
}
