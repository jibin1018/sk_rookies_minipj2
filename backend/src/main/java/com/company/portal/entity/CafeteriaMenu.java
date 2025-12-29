package com.company.portal.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "cafeteria_menus")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CafeteriaMenu {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private LocalDate menuDate;

    @Column(nullable = false, length = 20)
    private String mealType;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String menuItems;

    @Column
    private Integer calories;

    @Column(updatable = false)
    private Long createdBy;

    @Column(updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
