package com.ordernexus.order_nexus_backend.notification;

import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/notifications")

public class NotificationController {

    private final NotificationService service;

    public NotificationController(NotificationService service) {
        this.service = service;
    }

    @PostMapping
    public NotificationEntity create(@RequestBody NotificationRequest request) {
        return service.create(request);
    }

    @GetMapping
    public List<NotificationEntity> all() {
        return service.getAll();
    }

    @PutMapping("/read/{id}")
    public void markRead(@PathVariable Long id) {
        service.markRead(id);
    }

    @GetMapping("/unread-count")
    public long unreadCount() {
        return service.unreadCount();
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) {
        service.delete(id);
    }
}
