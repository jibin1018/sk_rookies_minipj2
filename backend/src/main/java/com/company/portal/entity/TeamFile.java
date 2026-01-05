package com.company.portal.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "team_files")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TeamFile extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "team_id", nullable = false)
    private Team team;

    @Column(name = "original_name", nullable = false)
    private String originalName;

    @Column(name = "stored_name", nullable = false)
    private String storedName;

    @Column(name = "file_path", nullable = false, length = 500)
    private String filePath;

    @Column(name = "file_size", nullable = false)
    private Long fileSize;

    @Column(name = "folder_path", length = 500)
    private String folderPath;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "uploaded_by", nullable = false)
    private Employee uploadedBy;

    @Column(name = "download_count")
    @Builder.Default
    private Integer downloadCount = 0;
}
