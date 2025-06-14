package com.newstoss.news.adapter.out.news.dto.v2;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class MLRelatedStockDTOv2 {
    @JsonProperty("stock_id")
    private String stockId;
    @JsonProperty("stock_name")
    private String stockName;
}
