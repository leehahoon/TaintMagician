// taint_strtok_strcpy_demo.c
// Build: gcc -O0 -g -fno-omit-frame-pointer -Wall -Wextra -o demo taint_strtok_strcpy_demo.c
// Run:   echo 'param=HELLO_WORLD' | ./demo
//       echo 'param=HELLO_WORLD&x=1' | ./demo
//       echo 'x=1&param=PAYLOAD' | ./demo

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static ssize_t read_full(int fd, char *buf, size_t cap) {
    // read()로 외부 입력이 buf 메모리에 들어감 (mem taint seed로 쓰기 좋음)
    ssize_t n = read(fd, buf, cap - 1);
    if (n <= 0) return n;
    buf[n] = '\0';
    return n;
}

// 위험 sink: src 포인터가 가리키는 문자열을 strcpy로 복사
static void danger_sink_strcpy(const char *src) {
    char dst[64];
    // 의도적으로 취약: 길이 체크 없음
    strcpy(dst, src);
    // 최적화 방지용 출력
    write(1, dst, strnlen(dst, sizeof(dst)));
    write(1, "\n", 1);
}

// "param=..." 값을 query string에서 찾아 반환 (strtok/strchr류 사용)
static const char *get_param_value(char *query, const char *key) {
    // query 예: "a=1&param=HELLO&b=2"
    // strtok_r은 내부적으로 query 메모리를 읽고, 토큰 포인터를 반환함
    char *save = NULL;
    for (char *tok = strtok_r(query, "&", &save); tok; tok = strtok_r(NULL, "&", &save)) {
        // tok 예: "param=HELLO"
        char *eq = strchr(tok, '=');
        if (!eq) continue;

        *eq = '\0';              // "param\0HELLO"
        const char *k = tok;
        const char *v = eq + 1;  // v는 tok 내부를 가리키는 포인터

        if (strcmp(k, key) == 0) {
            return v;            // ★ 반환 포인터 (taint 승격 필요 지점)
        }
    }
    return NULL;
}

int main(void) {
    char buf[512];
    memset(buf, 0, sizeof(buf));

    if (read_full(0, buf, sizeof(buf)) <= 0) {
        puts("no input");
        return 0;
    }

    // strtok_r이 buf를 직접 변형하므로, 분석에서 흔히 보는 패턴을 그대로 재현하려고
    // buf를 복사해서 파서에 넘김 (둘 중 어느 쪽을 taint seed로 잡아도 됨)
    char work[512];
    strncpy(work, buf, sizeof(work) - 1);
    work[sizeof(work) - 1] = '\0';

    const char *val = get_param_value(work, "param");
    if (!val) {
        puts("param not found");
        return 0;
    }

    // 최종 sink
    danger_sink_strcpy(val);
    return 0;
}