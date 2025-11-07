package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserStatisticsResponseDto {
    private Long totalUsers;
    private Long activeUsers;
    private int pendingUsers;
    private int suspendedUsers;
    private int enrolledOnBlockchain;
}
