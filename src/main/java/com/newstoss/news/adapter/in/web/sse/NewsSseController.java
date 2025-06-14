package com.newstoss.news.adapter.in.web.sse;

import com.newstoss.global.handler.CustomException;
import com.newstoss.global.jwt.JwtAuthenticationFilter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.UUID;

@CrossOrigin(origins = {
        "http://localhost:3000",
        "https://news-toss.vercel.app"
})
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/news/stream")
public class NewsSseController {
    private final SseEmitters sseEmitters;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    @GetMapping(produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream() {
        log.info("✅ [Controller] 클라이언트에서 SSE 연결 요청 들어옴");
        SseEmitter emitter = sseEmitters.add();
        try {
            emitter.send(SseEmitter.event()
                    .name("connect")
                    .data("connected"));
            System.out.println("✅ 연결 확인용 메시지 전송됨");
        } catch (IOException e) {
            System.out.println("❌ 연결 메시지 전송 실패: " + e.getMessage());
            log.error("❌ 연결 메시지 전송 실패: {}", e.getMessage());
            emitter.complete();
        }
        return emitter;
    }
}



