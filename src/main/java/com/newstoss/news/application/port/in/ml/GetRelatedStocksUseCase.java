package com.newstoss.news.application.port.in.ml;

import com.newstoss.news.adapter.in.web.dto.common.RelatedStockDTO;

import java.util.List;

public interface GetRelatedStocksUseCase {
    List<RelatedStockDTO> exec(String newsId);
}
