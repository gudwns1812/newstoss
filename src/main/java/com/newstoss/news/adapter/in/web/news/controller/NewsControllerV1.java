//package com.newstoss.news.adapter.in.web.news.controller;
//
//import com.newstoss.global.response.SuccessResponse;
//import com.newstoss.news.adapter.in.web.news.dto.v1.NewsDTOv1;
//import com.newstoss.news.adapter.in.web.news.dto.v1.RelatedNewsDTO;
//import com.newstoss.news.adapter.in.web.news.dto.v1.RelatedReportDTO;
//import com.newstoss.news.adapter.in.web.news.dto.v1.RelatedStockDTO;
//import com.newstoss.news.application.news.service.NewsServiceV1;
//import io.swagger.v3.oas.annotations.Operation;
//import io.swagger.v3.oas.annotations.tags.Tag;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.List;
//@Tag(name = "뉴스 API V1", description = "뉴스 관련 API V1")
//@RequestMapping("/api/news")
//@CrossOrigin("*")
//@RestController
//@RequiredArgsConstructor
//public class NewsControllerV1 {
//    private final NewsServiceV1 newsServiceV1;
//
//    @Operation(summary = "실시간 뉴스 조회", description = "최신 뉴스 10개를 조회합니다.")
//    @GetMapping("/top10")
//    public ResponseEntity<SuccessResponse<Object>> top10news(){
//        List<NewsDTOv1> topNews = newsServiceV1.getRealTimeNews();
//        return ResponseEntity.ok(new SuccessResponse<>(true, "실시간 뉴스 10개 불러오기 성공", topNews));
//    }
//
//    @Operation(summary = "뉴스 상세 조회", description = "특정 뉴스 ID에 해당하는 뉴스 상세 정보를 조회합니다.")
//    @GetMapping("/detail")
//    public ResponseEntity<SuccessResponse<Object>> newsdetail(@RequestParam String newsId){
//        NewsDTOv1 detailNews = newsServiceV1.getDetailNews(newsId);
//        return ResponseEntity.ok(new SuccessResponse<>(true,"뉴스 상세 조회 성공", detailNews));
//    }
//
//    @Operation(summary = "유사 뉴스 조회", description = "특정 뉴스와 유사한 과거 뉴스를 조회합니다.")
//    @GetMapping("/related/news")
//    public ResponseEntity<SuccessResponse<Object>> relatedNews(@RequestParam String newsId){
//        List<RelatedNewsDTO> news = newsServiceV1.getRelatedNews(newsId);
//        return ResponseEntity.ok(new SuccessResponse<>(true, "과거 유사 뉴스 조회 성공", news));
//    }
//
//    @Operation(summary = "뉴스 관련 종목 조회", description = "특정 뉴스와 연관된 주식 종목 리스트를 조회합니다.")
//    @GetMapping("/related/stocks")
//    public ResponseEntity<SuccessResponse<Object>> relatedStocks(@RequestParam String newsId){
//        List<RelatedStockDTO> stocks = newsServiceV1.getRelatedStock(newsId);
//        return ResponseEntity.ok(new SuccessResponse<>(true, "뉴스 관련 종목 조회 성공", stocks));
//    }
//
//    @Operation(summary = "뉴스 관련 리포트 조회", description = "특정 뉴스와 연관된 리포트 리스트를 조회합니다.(5개)")
//    @GetMapping("/related/report")
//    public ResponseEntity<SuccessResponse<Object>> relatedReport(@RequestParam String newsId){
//        List<RelatedReportDTO> report = newsServiceV1.getRelatedReport(newsId);
//        return ResponseEntity.ok(new SuccessResponse<>(true, "뉴스 관련 종목 조회 성공", report));
//    }
//}
