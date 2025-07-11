package com.newstoss.news.adapter.in.web.news.dto.v1;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RelatedNewsDTO {
    private String newsId;
    private Date date;
    private String title;
    private String content;
    private String url;
    private double similarity;
}