package com.ordernexus.order_nexus_backend.notification;

import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class NotificationService {

    private final NotificationRepository repository;

    public NotificationService(NotificationRepository repository) {
        this.repository = repository;
    }

    public NotificationEntity create(NotificationRequest request) {
        NotificationEntity n = new NotificationEntity();
        n.setOrderId(request.getOrderId());
        n.setMessage(request.getMessage());
        n.setReadStatus(false);
        return repository.save(n);
    }

    public List<NotificationEntity> getAll() {
        return repository.findAll();
    }

    public void markRead(Long id) {
        NotificationEntity n = repository.findById(id)
                .orElseThrow(() -> new RuntimeException("Notification not found"));
        n.setReadStatus(true);
        repository.save(n);
    }

    public long unreadCount() {
        return repository.countByReadStatusFalse();
    }

    public void delete(Long id) {
        repository.deleteById(id);
    }
}
