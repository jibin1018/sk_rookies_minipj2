package com.company.portal.repository;

import com.company.portal.entity.TeamFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TeamFileRepository extends JpaRepository<TeamFile, Long> {

    List<TeamFile> findByTeamId(Long teamId);

    List<TeamFile> findByTeamIdAndFolderPath(Long teamId, String folderPath);
}
