package com.company.portal.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "cafeteria_menus", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"menu_date", "meal_type"})
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CafeteriaMenu {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "menu_date", nullable = false)
    private LocalDate menuDate;

    @Column(name = "meal_type", length = 20)
    private String mealType;  // 조식, 중식, 석식

    @Column(name = "menu_items", nullable = false, columnDefinition = "TEXT")
    private String menuItems;

    @Column
    private Integer calories;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by")
    private Employee createdBy;

    @Column(name = "created_at")
    private java.time.LocalDateTime createdAt;

    @OneToMany(mappedBy = "menu", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<MenuReview> reviews = new ArrayList<>();

    @PrePersist
    protected void onCreate() {
        createdAt = java.time.LocalDateTime.now();
    }
}
